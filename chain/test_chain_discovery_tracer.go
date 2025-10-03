package chain

import (
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain/types"
)

// testChainContractDiscoveryTracer implements TestChainTracer, capturing information regarding contract deployments and
// self-destructs. It is a special tracer that is used internally by each TestChain. It subscribes to its block-related
// events in order to power the TestChain's contract deployment related events.
type testChainContractDiscoveryTracer struct {
	// results describes the results being currently captured.
	results []types.DeployedContractBytecode

	// callDepth refers to the current EVM depth during tracing.
	callDepth uint64

	// evm refers to the last tracing.VMContext captured.
	evmContext *tracing.VMContext

	// pendingCallFrames represents per-call-frame data deployment information being captured by the tracer.
	// This is committed as each call frame succeeds, so that contract deployments which later encountered an error
	// and reverted are not considered. The index of each element in the array represents its call frame depth.
	pendingCallFrames []*testChainContractDiscoveryTracerCallFrame

	// nativeTracer is the underlying tracer interface that the deployment tracer follows
	nativeTracer *TestChainTracer
}

// testChainContractDiscoveryTracerCallFrame represents per-call-frame data traced by a testChainContractDiscoveryTracer.
type testChainContractDiscoveryTracerCallFrame struct {
	// results describes the results being currently captured.
	results []types.DeployedContractBytecode
}

// newtestChainContractDiscoveryTracer creates a testChainContractDiscoveryTracer
func newTestChainContractDiscoveryTracer() *testChainContractDiscoveryTracer {
	tracer := &testChainContractDiscoveryTracer{}
	innerTracer := &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: tracer.OnTxStart,
			OnTxEnd:   tracer.OnTxEnd,
			OnEnter:   tracer.OnEnter,
			OnExit:    tracer.OnExit,
			OnOpcode:  tracer.OnOpcode,
		},
	}
	tracer.nativeTracer = &TestChainTracer{Tracer: innerTracer, CaptureTxEndSetAdditionalResults: tracer.CaptureTxEndSetAdditionalResults}

	return tracer

}

// NativeTracer returns the underlying TestChainTracer.
func (t *testChainContractDiscoveryTracer) NativeTracer() *TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *testChainContractDiscoveryTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our tracer state
	t.results = make([]types.DeployedContractBytecode, 0)
	t.pendingCallFrames = make([]*testChainContractDiscoveryTracerCallFrame, 0)

	// Store our evm reference
	t.evmContext = vm
}

// OnTxEnd is called upon the end of transaction execution, as defined by tracers.Tracer.
func (t *testChainContractDiscoveryTracer) OnTxEnd(receipt *coretypes.Receipt, err error) {

}

// OnEnter is called upon entering of the call frame, as defined by tracers.Tracer.
func (t *testChainContractDiscoveryTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Create our call frame struct to track data for this call frame.
	callFrameData := &testChainContractDiscoveryTracerCallFrame{}
	t.pendingCallFrames = append(t.pendingCallFrames, callFrameData)

	// Update call depth if this is not the top-level call frame
	isTopLevelFrame := depth == 0
	if !isTopLevelFrame {
		t.callDepth++
	}

	// If this is a contract creation, record the `to` address as a pending deployment (if it succeeds upon exit,
	// we commit it).
	if typ == byte(vm.CALL) || typ == byte(vm.STATICCALL) || typ == byte(vm.DELEGATECALL) {
		callFrameData.results = append(callFrameData.results, types.DeployedContractBytecode{
			Address:         to,
			RuntimeBytecode: t.evmContext.StateDB.GetCode(to),
		})
	}
}

// OnExit is called after a call to finalize tracing completes for the top of a call frame, as defined by tracers.Tracer.
func (t *testChainContractDiscoveryTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// If we didn't encounter any errors and this is the top level call frame, commit all the results
	if isTopLevelFrame {
		t.results = append(t.results, t.pendingCallFrames[t.callDepth].results...)
	} else {
		// If we didn't encounter an error in this call frame, we push our captured data up one frame.
		if err == nil {
			t.pendingCallFrames[t.callDepth-1].results = append(t.pendingCallFrames[t.callDepth-1].results, t.pendingCallFrames[t.callDepth].results...)
		}

		// We're exiting the current frame, so remove our frame data and decrement the call depth.
		t.pendingCallFrames = t.pendingCallFrames[:t.callDepth]
		t.callDepth--
	}

}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *testChainContractDiscoveryTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *testChainContractDiscoveryTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Set our results. This is an internal tracer used by the test chain, so we don't need to use the
	// "additional results" field as other tracers might, we instead populate the field explicitly defined.
	results.ContractDiscoverys = t.results
}

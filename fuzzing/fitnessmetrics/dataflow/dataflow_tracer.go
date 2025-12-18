package dataflow

import (
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/logging"
)

// dataflowTracerResultsKey describes the key to use when storing tracer results in call message results, or when
// querying them.
const dataflowTracerResultsKey = "DataflowTracerResults"

// GetDataflowTracerResults obtains DataflowSet stored by a DataflowTracer from message results. This is nil if
// no DataflowSet were recorded by a tracer (e.g. DataflowTracer was not attached during this message execution).
func GetDataflowTracerResults(messageResults *types.MessageResults) *DataflowSet {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[dataflowTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*DataflowSet); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveDataflowTracerResults removes DataflowSet stored by a DataflowTracer from message results.
func RemoveDataflowTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, dataflowTracerResultsKey)
}

// DataflowTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type DataflowTracer struct {
	// dataflowSet describes the dataflow recorded. Call frames which errored are not recorded.
	dataflowSet *DataflowSet

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*dataflowTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer

	// hashTracebackMap maps storage the lower 32 bytes of the original data of a hash from KECCAK256 operation.
	// hashTracebackMap map[common.Hash]common.Hash
	// hasher is the keccak hasher used to hash data.
	// hasher crypto.KeccakState
}

// dataflowTracerCallFrameState tracks state across call frames in the tracer.
type dataflowTracerCallFrameState struct {
	// initialized tracks whether or not this has happened yet.
	initialized bool
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// address is used by OnOpcode to cache the result of scope.Address(), which is slow.
	// It records the address of the current contract.
	address common.Address
}

// NewDataflowTracer returns a new DataflowTracer.
func NewDataflowTracer() *DataflowTracer {
	tracer := &DataflowTracer{
		dataflowSet:     NewDataflowSet(),
		callFrameStates: make([]*dataflowTracerCallFrameState, 0),
		// hashTracebackMap: make(map[common.Hash]common.Hash),
		// hasher:           crypto.NewKeccakState(),
	}
	nativeTracer := &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: tracer.OnTxStart,
			OnEnter:   tracer.OnEnter,
			OnExit:    tracer.OnExit,
			OnOpcode:  tracer.OnOpcode,
		},
	}
	tracer.nativeTracer = &chain.TestChainTracer{Tracer: nativeTracer, CaptureTxEndSetAdditionalResults: tracer.CaptureTxEndSetAdditionalResults}
	return tracer
}

// NativeTracer returns the underlying TestChainTracer.
func (t *DataflowTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *DataflowTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.dataflowSet = NewDataflowSet()
	// t.hashTracebackMap = make(map[common.Hash]common.Hash)
	t.callFrameStates = make([]*dataflowTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter is called upon entering of the call frame, as defined by tracers.Tracer.
func (t *DataflowTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	isTopLevelFrame := depth == 0
	if !isTopLevelFrame {
		t.callDepth++
	}
	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &dataflowTracerCallFrameState{
		create:  typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		address: to,
	})
}

// OnExit is called upon exiting of the call frame, as defined by tracers.Tracer.
func (t *DataflowTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	// currentCallFrameState := t.callFrameStates[t.callDepth]
	currentDataflowSet := t.dataflowSet // DataflowSet is not per frame

	if reverted {
		// Dataflow analysis doesn't differentiate between reverted or successful transactions at this level
		// So we won't reset anything here.
		currentDataflowSet.RevertAll()
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our dataflow sets up one call frame.
	var dataflowUpdateErr error
	if isTopLevelFrame {
		// For dataflow, it's global, no need to merge from sub-frames.
		// However, the interface expects an update from a sub-frame's dataflow.
		// Since we handle a global dataflowSet, we don't need to do anything here for merging up.
	} else {
		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}

	if dataflowUpdateErr != nil {
		logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set during OnExit", dataflowUpdateErr)
	}
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *DataflowTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if !callFrameState.initialized {
		callFrameState.initialized = true
	}

	scopeContext := scope.(*vm.ScopeContext)

	if vm.OpCode(op) == vm.SLOAD || vm.OpCode(op) == vm.SSTORE {
		slot := scopeContext.Stack.Back(0)
		storageAddress := scopeContext.Contract.Address()
		codeAddress := callFrameState.address
		// Record storage read/write for this location in our dataflow set.
		var updateErr error
		if vm.OpCode(op) == vm.SLOAD {
			_, updateErr = t.dataflowSet.SetRead(storageAddress, slot, codeAddress, callFrameState.create, pc)
		} else { // SSTORE
			_, updateErr = t.dataflowSet.SetWrite(storageAddress, slot, codeAddress, callFrameState.create, pc)
		}
		if updateErr != nil {
			logging.GlobalLogger.Panic("Dataflow tracer failed to update dataflow set while tracing state", updateErr)
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *DataflowTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[dataflowTracerResultsKey] = t.dataflowSet
}

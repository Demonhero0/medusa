package tokenflow

import (
	"encoding/hex"
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/logging"
	"github.com/holiman/uint256"
)

// tokenflowTracerResultsKey describes the key to use when storing tracer results in call message results,
// or when querying them.
const tokenflowTracerResultsKey = "TokenflowTracerResults"

// GetTokenflowTracerResults obtains TokenflowSet stored by a TokenflowTracer from message results.
// This is nil if no TokenflowSet were recorded by a tracer (e.g. TokenflowTracer was not attached during
// this message execution).
func GetTokenflowTracerResults(messageResults *types.MessageResults) *TokenflowSet {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[tokenflowTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*TokenflowSet); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveTokenflowTracerResults removes TokenflowSet stored by a TokenflowTracer from message results.
func RemoveTokenflowTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, tokenflowTracerResultsKey)
}

// TokenflowTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type TokenflowTracer struct {
	// tokenflowSet describes the dataflow recorded. Call frames which errored are not recorded.
	tokenflowSet *TokenflowSet

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*tokenflowTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer
}

// tokenflowTracerCallFrameState tracks state across call frames in the tracer.
type tokenflowTracerCallFrameState struct {
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingTokenflowSet describes the storage-write set recorded for this call frame.
	pendingTokenflowSet *TokenflowSet

	// address is the address of the code being executed.
	address common.Address
}

// NewTokenflowTracer returns a new TokenflowTracer.
func NewTokenflowTracer() *TokenflowTracer {
	tracer := &TokenflowTracer{
		tokenflowSet:    NewTokenflowSet(),
		callFrameStates: make([]*tokenflowTracerCallFrameState, 0),
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
func (t *TokenflowTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *TokenflowTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.tokenflowSet = NewTokenflowSet()
	t.callFrameStates = make([]*tokenflowTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter is called upon entering of the call frame, as defined by tracers.Tracer.
func (t *TokenflowTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	isTopLevelFrame := depth == 0
	if !isTopLevelFrame {
		t.callDepth++
	}
	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &tokenflowTracerCallFrameState{
		create:              typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingTokenflowSet: NewTokenflowSet(),
		address:             to,
	})
}

// OnExit is called upon exiting of the call frame, as defined by tracers.Tracer.
func (t *TokenflowTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentPendingTokenflowSet := currentCallFrameState.pendingTokenflowSet

	// If we encountered an error in this call frame, mark all tokenflow as reverted.
	if reverted {
		currentPendingTokenflowSet.RevertAll()
	}

	isTopLevelFrame := depth == 0
	var updateErr error
	if isTopLevelFrame {
		_, updateErr = t.tokenflowSet.Update(currentPendingTokenflowSet)
	} else {
		_, updateErr = t.callFrameStates[t.callDepth-1].pendingTokenflowSet.Update(currentPendingTokenflowSet)
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
	if updateErr != nil {
		logging.GlobalLogger.Panic("Tokenflow tracer failed to update tokenflow set during OnExit", updateErr)
	}
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *TokenflowTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]
	scopeContext := scope.(*vm.ScopeContext)

	if vm.OpCode(op) == vm.CALL {
		addr, value, inOffset, inSize := scopeContext.Stack.Back(1), scopeContext.Stack.Back(2), scopeContext.Stack.Back(3), scopeContext.Stack.Back(4)
		toAddr := common.Address(addr.Bytes20())
		// Get the arguments from the memory.
		args := scopeContext.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())
		storageAddress := scopeContext.Contract.Address()
		codeAddress := callFrameState.address

		if value.Cmp(uint256.NewInt(0)) > 0 {
			_, updateErr := callFrameState.pendingTokenflowSet.SetTokenFlow(storageAddress, codeAddress, callFrameState.create, pc, value, storageAddress, toAddr, common.HexToAddress("0x"))
			if updateErr != nil {
				logging.GlobalLogger.Panic("Tokenflow tracer failed to update tokenflow set while tracing state", updateErr)
			}
		}

		if len(args) >= 4 {
			if hex.EncodeToString(args[:4]) == "a9059cbb" && len(args) == 68 {
				// This is a token transfer, parse the arguments.
				to := common.BytesToAddress(args[4:36])
				amount := uint256.NewInt(0).SetBytes(args[36:68])

				// Set the token flow.
				_, updateErr := callFrameState.pendingTokenflowSet.SetTokenFlow(storageAddress, codeAddress, callFrameState.create, pc, amount, storageAddress, to, toAddr)
				if updateErr != nil {
					logging.GlobalLogger.Panic("Tokenflow tracer failed to update tokenflow set while tracing state", updateErr)
				}
			} else if hex.EncodeToString(args[:4]) == "23b872dd" && len(args) == 100 {
				// This is a token transfer from, parse the arguments.
				from := common.BytesToAddress(args[4:36])
				to := common.BytesToAddress(args[36:68])
				amount := uint256.NewInt(0).SetBytes(args[68:100])

				// Set the token flow.
				_, updateErr := callFrameState.pendingTokenflowSet.SetTokenFlow(storageAddress, codeAddress, callFrameState.create, pc, amount, from, to, toAddr)
				if updateErr != nil {
					logging.GlobalLogger.Panic("Tokenflow tracer failed to update tokenflow set while tracing state", updateErr)
				}
			}
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *TokenflowTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[tokenflowTracerResultsKey] = t.tokenflowSet
}

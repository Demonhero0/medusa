package storagewrite

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

// storageWriteTracerResultsKey describes the key to use when storing tracer results in call message results,
// or when querying them.
const storageWriteTracerResultsKey = "StorageWriteTracerResults"

// GetStorageWriteTracerResults obtains StorageWriteSet stored by a StorageWriteTracer from message results.
// This is nil if no StorageWriteSet were recorded by a tracer (e.g. StorageWriteTracer was not attached during
// this message execution).
func GetStorageWriteTracerResults(messageResults *types.MessageResults) *StorageWriteSet {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[storageWriteTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*StorageWriteSet); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveStorageWriteTracerResults removes StorageWriteSet stored by a StorageWriteTracer from message results.
func RemoveStorageWriteTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, storageWriteTracerResultsKey)
}

// StorageWriteTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type StorageWriteTracer struct {
	// storageWriteSet describes the dataflow recorded. Call frames which errored are not recorded.
	storageWriteSet *StorageWriteSet

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*storageWriteTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer
}

// storageWriteTracerCallFrameState tracks state across call frames in the tracer.
type storageWriteTracerCallFrameState struct {
	// initialized tracks whether or not this has happened yet.
	initialized bool
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingStorageWriteSet describes the storage-write set recorded for this call frame.
	pendingStorageWriteSet *StorageWriteSet

	// address is the address of the code being executed.
	address common.Address
}

// NewStorageWriteTracer returns a new StorageWriteTracer.
func NewStorageWriteTracer() *StorageWriteTracer {
	tracer := &StorageWriteTracer{
		storageWriteSet: NewStorageWriteSet(),
		callFrameStates: make([]*storageWriteTracerCallFrameState, 0),
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
func (t *StorageWriteTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *StorageWriteTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.storageWriteSet = NewStorageWriteSet()
	t.callFrameStates = make([]*storageWriteTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter is called upon entering of the call frame, as defined by tracers.Tracer.
func (t *StorageWriteTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	isTopLevelFrame := depth == 0
	if !isTopLevelFrame {
		t.callDepth++
	}
	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &storageWriteTracerCallFrameState{
		create:                 typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingStorageWriteSet: NewStorageWriteSet(),
		address:                to,
	})
}

// OnExit is called upon exiting of the call frame, as defined by tracers.Tracer.
func (t *StorageWriteTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentStorageWriteSet := currentCallFrameState.pendingStorageWriteSet

	// If we encountered an error in this call frame, mark all storage-write as reverted.
	if reverted {
		currentStorageWriteSet.RevertAll()
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our storage-write sets up one call frame.
	var updateErr error
	if isTopLevelFrame {
		_, updateErr = t.storageWriteSet.Update(currentStorageWriteSet)
	} else {
		_, updateErr = t.callFrameStates[t.callDepth-1].pendingStorageWriteSet.Update(currentStorageWriteSet)

		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
	if updateErr != nil {
		logging.GlobalLogger.Panic("StorageWrite tracer failed to update storage-write set during OnExit", updateErr)
	}
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *StorageWriteTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	scopeContext := scope.(*vm.ScopeContext)

	if vm.OpCode(op) == vm.SSTORE {
		slot := scopeContext.Stack.Back(0)
		value := scopeContext.Stack.Back(1)
		storageAddress := scopeContext.Contract.Address()
		codeAddress := callFrameState.address

		// Record storage write for this location in our storage-write set.
		_, updateErr := callFrameState.pendingStorageWriteSet.SetWrite(storageAddress, slot, value, codeAddress, callFrameState.create, pc)
		if updateErr != nil {
			logging.GlobalLogger.Panic("StorageWrite tracer failed to update storage-write set while tracing state", updateErr)
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *StorageWriteTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[storageWriteTracerResultsKey] = t.storageWriteSet
}

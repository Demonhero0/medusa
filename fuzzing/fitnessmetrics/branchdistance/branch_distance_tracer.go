package branchdistance

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/logging"
	"github.com/holiman/uint256"
)

// coverageTracerResultsKey describes the key to use when storing tracer results in call message results, or when
// querying them.
const branchDistanceTracerResultsKey = "BranchDistanceTracerResults"

// GetBranchDistanceTracerResults obtains BranchDistanceMaps stored by a BranchDistanceTracer from message results. This is nil if
// no BranchDistanceMaps were recorded by a tracer (e.g. BlockCoverageTracer was not attached during this message execution).
func GetBranchDistanceTracerResults(messageResults *types.MessageResults) *BranchDistanceMaps {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[branchDistanceTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*BranchDistanceMaps); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveBranchDistanceTracerResults removes BranchDistanceMaps stored by a BranchDistanceTracer from message results.
func RemoveBranchDistanceTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, branchDistanceTracerResultsKey)
}

// BranchDistanceTracer implements tracers.Tracer to collect information such as branch distance maps
// for fuzzing campaigns from EVM execution traces.
type BranchDistanceTracer struct {
	// branchDistanceMaps describes the execution coverage recorded. Call frames which errored are not recorded.
	branchDistanceMaps *BranchDistanceMaps

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*branchDistanceTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// branchMaps stores branch map for each contract code
	branchMaps map[common.Hash]*BranchMap

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer
}

var DD *uint256.Int = uint256.NewInt(1)

type BranchDistanceStatus int

const (
	FOUND BranchDistanceStatus = iota
	NOTFOUND
	NOTJUMPI
	STACKOUTOFSCOPE
	ENDWITHCALL
)

var branchDistanceStatusToStr = [5]string{
	FOUND:           "FOUND",
	NOTFOUND:        "NOTFOUND",
	NOTJUMPI:        "NOTJUMPI",
	STACKOUTOFSCOPE: "STACKOUTOFSCOPE",
	ENDWITHCALL:     "ENDWITHCALL",
}

func IsFoundDistance(x BranchDistanceStatus) bool {
	return x == FOUND || x == ENDWITHCALL
}

type Operation struct {
	opcode   vm.OpCode
	tmpStack []uint256.Int
}

// branchDistanceTracerCallFrameState tracks state across call frames in the tracer.
type branchDistanceTracerCallFrameState struct {
	// initialized tracks whether or not this has happened yet.
	initialized bool
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingBranchDistanceMap describes the coverage maps recorded for this call frame.

	pendingBranchDistanceMap *BranchDistanceMaps

	// lookupHash describes the hash used to look up the ContractCoverageMap being updated in this frame.
	lookupHash *common.Hash

	cachedOperations []Operation

	// address is used by OnOpcode to cache the result of scope.Address(), which is slow.
	// It records the address of the current contract.
	address common.Address
}

// NewBranchDistanceTracer returns a new CoverageTracer.
func NewBranchDistanceTracer(contracts fuzzerTypes.Contracts) *BranchDistanceTracer {
	// Create a map of block maps for each contract code
	branchMaps := make(map[common.Hash]*BranchMap)
	for _, contract := range contracts {
		compiledContract := contract.CompiledContract()

		initBytecode := compiledContract.InitBytecode
		initBytecodeHash := getContractBranchDistanceMapHash(initBytecode, true)

		runtimeBytecode := compiledContract.RuntimeBytecode
		runtimeBytecodeHash := getContractBranchDistanceMapHash(runtimeBytecode, false)

		// remove runtime bytecode (including metadata here) from init bytecode
		runtimeBytecodeOffset := bytes.LastIndex(initBytecode, runtimeBytecode)
		if runtimeBytecodeOffset != -1 {
			initBytecode = initBytecode[:runtimeBytecodeOffset]
		}
		// remove metadata from runtime bytecode
		runtimeBytecode = compilationTypes.RemoveContractMetadata(runtimeBytecode)

		branchMaps[initBytecodeHash] = GetBranchMapFromBytecode(initBytecode)
		branchMaps[runtimeBytecodeHash] = GetBranchMapFromBytecode(runtimeBytecode)
	}

	tracer := &BranchDistanceTracer{
		branchDistanceMaps: NewBranchDistanceMaps(),
		callFrameStates:    make([]*branchDistanceTracerCallFrameState, 0),
		branchMaps:         branchMaps,
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
func (t *BranchDistanceTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *BranchDistanceTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.branchDistanceMaps = NewBranchDistanceMaps()
	t.callFrameStates = make([]*branchDistanceTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter initializes the tracing operation for the top of a call frame, as defined by tracers.Tracer.
func (t *BranchDistanceTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Increment call frame depth if it is not the top level call frame
	if !isTopLevelFrame {
		t.callDepth++
	}

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &branchDistanceTracerCallFrameState{
		create:                   typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingBranchDistanceMap: NewBranchDistanceMaps(),
	})
}

// OnExit is called after a call to finalize tracing completes for the top of a call frame, as defined by tracers.Tracer.
func (t *BranchDistanceTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentDistanceMap := currentCallFrameState.pendingBranchDistanceMap

	if reverted {
		currentDistanceMap.RevertAll()
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our distance maps up one call frame.
	var distanceUpdateErr error

	if isTopLevelFrame {
		// Update the final distance map if this is the top level call frame
		_, distanceUpdateErr = t.branchDistanceMaps.Update(currentDistanceMap)
	} else {
		// Move distance up one call frame
		_, distanceUpdateErr = t.callFrameStates[t.callDepth-1].pendingBranchDistanceMap.Update(currentDistanceMap)

		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
	if distanceUpdateErr != nil {
		logging.GlobalLogger.Panic("Branch distance tracer failed to update distance map during OnExit", distanceUpdateErr)
	}
}

func (t *branchDistanceTracerCallFrameState) backPropagationToFindDistance() (*uint256.Int, BranchDistanceStatus, error) {
	// require that the last operation is jumpi
	lastOperation := t.cachedOperations[len(t.cachedOperations)-1]
	if vm.OpCode(lastOperation.opcode) != vm.JUMPI {
		return uint256.NewInt(0), NOTJUMPI, fmt.Errorf("the last opeartion is not JUMPI when performing backPropagationToFindDistance")
	}
	// fmt.Printf("------------------------------------\n")

	sourceIndex := len(lastOperation.tmpStack) - 2

	baseValue := new(uint256.Int).Set(&lastOperation.tmpStack[sourceIndex])
	bs := NOTFOUND
	diff := uint256.NewInt(0)
	for i := len(t.cachedOperations) - 1; i > len(t.cachedOperations)-40 && i >= 0; i-- {
		o := t.cachedOperations[i]
		op := vm.OpCode(o.opcode)
		stack := o.tmpStack
		stackLen := len(stack)
		switch {
		// deal with the case of comparison operation
		case (op == vm.LT || op == vm.GT || op == vm.EQ) && sourceIndex == stackLen-2:
			x, y := &stack[stackLen-1], &stack[stackLen-2]
			if x.Gt(y) { // if x > y
				diff = diff.Sub(x, y)
			} else { // if x <= y
				diff = diff.Sub(y, x)
			}
			bs = FOUND
		case (op == vm.SLT || op == vm.SGT) && sourceIndex == stackLen-2:
			x, y := &stack[stackLen-1], &stack[stackLen-2]
			if x.Sgt(y) { // if x > y
				diff = diff.Sub(x, y)
			} else { // if x <= y
				diff = diff.Sub(y, x)
			}
			bs = FOUND
		case (op == vm.AND) && sourceIndex == stackLen-2:
			x, y := &stack[stackLen-1], &stack[stackLen-2]
			if x.Gt(y) {
				diff = new(uint256.Int).Set(y)
			} else {
				diff = new(uint256.Int).Set(x)
			}
			bs = FOUND
		case (op == vm.OR) && sourceIndex == stackLen-2:
			x, y := &stack[stackLen-1], &stack[stackLen-2]
			if x.Gt(y) {
				diff = new(uint256.Int).Set(x)
			} else {
				diff = new(uint256.Int).Set(y)
			}
			bs = FOUND
		case (op == vm.NOT) && sourceIndex == stackLen-1:
			if baseValue.Cmp(uint256.NewInt(0)) == 0 {
				baseValue = uint256.NewInt(1)
			} else {
				baseValue = uint256.NewInt(0)
			}
		// deal with the case of calculation operation
		case (o.opcode >= vm.ADD && o.opcode <= vm.MULMOD) && sourceIndex == stackLen-2:
			diff = new(uint256.Int).Set(baseValue)
			bs = FOUND
		case (op == vm.ISZERO) && sourceIndex == stackLen-1:
			diff = new(uint256.Int).Set(baseValue)
			bs = FOUND
		case (op == vm.SELFBALANCE) && sourceIndex == stackLen:
			diff = new(uint256.Int).Set(baseValue)
			bs = FOUND
		// deal with dup operation
		case (o.opcode >= vm.DUP1 && o.opcode <= vm.DUP16) && sourceIndex == stackLen: // because dup will expand the stack, we make sourceIndex == stackLen to represent that the dup is opearting the sourceIndex
			sourceIndex = stackLen - 1 - (int(o.opcode) - int(vm.DUP1))
		// deal with swap operation
		case (o.opcode >= vm.SWAP1 && o.opcode <= vm.SWAP16):
			if sourceIndex == stackLen-1 {
				sourceIndex = stackLen - 1 - (int(o.opcode) - int(vm.SWAP1) + 1)
			} else if sourceIndex == stackLen-1-(int(o.opcode)-int(vm.SWAP1)+1) {
				sourceIndex = stackLen - 1
			}
		// deal with push
		case (op >= vm.PUSH1 && op <= vm.PUSH32) && sourceIndex == stackLen:
			diff = new(uint256.Int).Set(baseValue)
			bs = FOUND
		// deal with call
		case (op == vm.CALL) && sourceIndex == stackLen-7:
			diff = new(uint256.Int).Set(&lastOperation.tmpStack[len(lastOperation.tmpStack)-2])
			bs = ENDWITHCALL
		case (op == vm.STATICCALL) && sourceIndex == stackLen-6:
			diff = new(uint256.Int).Set(&lastOperation.tmpStack[len(lastOperation.tmpStack)-2])
			bs = ENDWITHCALL
		case (op == vm.DELEGATECALL) && sourceIndex == stackLen-6:
			diff = new(uint256.Int).Set(&lastOperation.tmpStack[len(lastOperation.tmpStack)-2])
			bs = ENDWITHCALL
		case (op == vm.CALLVALUE) && sourceIndex == stackLen:
			diff = new(uint256.Int).Set(&t.cachedOperations[i+1].tmpStack[sourceIndex])
			bs = FOUND
		}
		if sourceIndex > stackLen {
			return diff, STACKOUTOFSCOPE, fmt.Errorf("sourceIndex (%d) out of scope (stackLen = %d)", sourceIndex, stackLen)
		}
		// fmt.Printf("opcode: %v, sourceIndex: %v, stackLen:%v, stacks:[ ", op.String(), sourceIndex, stackLen)
		// for j := len(o.tmpStack) - 1; j > len(o.tmpStack)-10 && j >= 0; j-- {
		// 	if j == sourceIndex {
		// 		red := "\033[31m"
		// 		reset := "\033[0m"
		// 		fmt.Printf(red+"%s,"+reset, o.tmpStack[j].String())
		// 	} else {
		// 		fmt.Printf("%s,", o.tmpStack[j].String())
		// 	}
		// }
		// fmt.Printf("]\n")

		if IsFoundDistance(bs) {
			return diff, bs, nil
		}
	}
	return diff, NOTFOUND, nil
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *BranchDistanceTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if !callFrameState.initialized {
		callFrameState.initialized = true
		callFrameState.address = scope.Address()
	}

	// We can cast OpContext to ScopeContext because that is the type passed to OnOpcode.
	scopeContext := scope.(*vm.ScopeContext)

	// If there is code we're executing and opcode is JUMPI, collect coverage.
	if len(scopeContext.Contract.Code) > 0 {
		tmpOperation := Operation{
			opcode:   vm.OpCode(op),
			tmpStack: make([]uint256.Int, len(scopeContext.Stack.Data())),
		}
		copy(tmpOperation.tmpStack, scopeContext.Stack.Data())
		callFrameState.cachedOperations = append(callFrameState.cachedOperations, tmpOperation)

		if vm.OpCode(op) == vm.JUMPI {
			// Obtain our contract coverage map lookup hash.
			if callFrameState.lookupHash == nil {
				lookupHash := getContractBranchDistanceMapHash(scopeContext.Contract.Code, callFrameState.create)
				callFrameState.lookupHash = &lookupHash
			}

			// Obtain branch id using condition from stack.
			cond := scopeContext.Stack.Back(1)
			branchMap, exists := t.branchMaps[*callFrameState.lookupHash]
			if !exists {
				// This contract is not in our list of contracts to trace.
				return
			}
			branchSize := branchMap.Size()

			var distanceToCondIsZero *uint256.Int
			var distanceToCondIsNotZero *uint256.Int
			var vmErr error

			if !cond.IsZero() { // cond != 0, jump to pos - 1, distanceCondIsZero = 0, distanceCondIsNotZero = DD
				if cond.Gt(uint256.NewInt(1)) {
					distanceToCondIsZero = new(uint256.Int).Set(cond)
				} else {
					// var branchDistanceStatus BranchDistanceStatus
					distanceToCondIsZero, _, vmErr = callFrameState.backPropagationToFindDistance()
					if vmErr != nil {
						panic(fmt.Sprintf("error in backPropagationToFindDistance %v", vmErr))
					}
				}
				// add K distance
				distanceToCondIsZero = new(uint256.Int).Add(distanceToCondIsZero, DD)
				// deal with the distance of another branch
				distanceToCondIsNotZero = uint256.NewInt(0)
			} else { // cond == 0, not jumping, distanceCondIsZero = 0, distanceCondIsNotZero = DD
				// deal with the distance of another branch
				distanceToCondIsZero = uint256.NewInt(0)

				distanceToCondIsNotZero, _, vmErr = callFrameState.backPropagationToFindDistance()
				if vmErr != nil {
					panic(fmt.Sprintf("error in backPropagationToFindDistance %v", vmErr))
				}
				// add K distance
				distanceToCondIsNotZero = new(uint256.Int).Add(distanceToCondIsNotZero, DD)
			}
			// fmt.Printf("JUMPI, COND: %s, DistanceToCondIsZero: %s, DistanceToCondIsNotZero: %s .\n", cond.String(), distanceToCondIsZero.String(), distanceToCondIsNotZero.String())
			// fmt.Println("------------------")

			// Record branch coverage for this path of this instruction location in our map.
			_, coverageUpdateErr := callFrameState.pendingBranchDistanceMap.SetAt(scopeContext.Contract.Address(), *callFrameState.lookupHash, branchSize, branchMap.GetBranchId(pc, false), distanceToCondIsZero)
			if coverageUpdateErr != nil {
				logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map while tracing state", coverageUpdateErr)
			}
			_, coverageUpdateErr = callFrameState.pendingBranchDistanceMap.SetAt(scopeContext.Contract.Address(), *callFrameState.lookupHash, branchSize, branchMap.GetBranchId(pc, true), distanceToCondIsNotZero)
			if coverageUpdateErr != nil {
				logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map while tracing state", coverageUpdateErr)
			}
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *BranchDistanceTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[branchDistanceTracerResultsKey] = t.branchDistanceMaps
}

package bugdetector

import (
	"fmt"

	"github.com/crytic/medusa-geth/core/vm"
)

const BLOCK_DEPENDENCY_ID = "BLOCK_DEPENDENCY"

func isBlockDependencyTaintSource(opcode byte) bool {
	return opcode == 0x42 || // BLOCKHASH
		opcode == 0x43 || // COINBASE
		opcode == 0x44 || // TIMESTAMP
		opcode == 0x45 || // NUMBER
		opcode == 0x46 || // DIFFICULTY
		opcode == 0x47 // GASLIMIT
}

func isBlockDependencyTaintSunk(opcode byte, ta *TaintAnalyzer) bool {

	switch vm.OpCode(opcode) {
	case vm.LT, vm.GT, vm.SLT, vm.SGT, vm.EQ:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0) || ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 1)
	case vm.ISZERO:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0)
	case vm.CALL, vm.CALLCODE:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 1) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 2) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 3) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 4)
	case vm.DELEGATECALL, vm.STATICCALL:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 1) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 2) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 3)
	case vm.CREATE:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 1) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 2)
	case vm.CREATE2:
		return ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 0) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 1) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 2) ||
			ta.IsTaintedByString(BLOCK_DEPENDENCY_ID, 3)
	default:
		return false
	}
}

func detect_block_dependency(tracer *BugDetectorTracer, pc uint64, opcode byte) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	if isBlockDependencyTaintSource(opcode) {
		lastCall.taintAnalyzer.AddTaintSourceByString(BLOCK_DEPENDENCY_ID)
	} else if isBlockDependencyTaintSunk(opcode, lastCall.taintAnalyzer) {
		id := fmt.Sprintf("BLOCKDEPENDENCY-%s-%d-%s", lastCall.codeAddress, pc, vm.OpCode(opcode).String())
		tracer.bugMap.CoverBug(id)
	}

}

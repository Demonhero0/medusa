package bugdetector

import (
	"fmt"

	"github.com/crytic/medusa-geth/core/tracing"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/holiman/uint256"
)

const OVERFLOW_ID string = "OVERFLOW"

func isOverflowTaintSource(opcode byte, scope tracing.OpContext) bool {
	scopeContext := scope.(*vm.ScopeContext)
	switch vm.OpCode(opcode) {
	case vm.ADD:
		a := scopeContext.Stack.Back(0)
		b := scopeContext.Stack.Back(1)
		sum := new(uint256.Int).Add(a, b)
		if sum.Lt(a) || sum.Lt(b) {
			return true
		}
	case vm.SUB:
		a := scopeContext.Stack.Back(0)
		b := scopeContext.Stack.Back(1)
		if a.Lt(b) {
			return true
		}
	case vm.MUL:
		a := scopeContext.Stack.Back(0)
		b := scopeContext.Stack.Back(1)
		if a.IsZero() || b.IsZero() {
			return false
		} else {
			product := new(uint256.Int).Mul(a, b)
			if product.Lt(a) || product.Lt(b) {
				return true
			}
		}
	}

	return false
}

func isOverflowTaintSunk(opcode byte, ta *TaintAnalyzer) bool {
	switch vm.OpCode(opcode) {
	case vm.LT, vm.GT, vm.SLT, vm.SGT, vm.EQ:
		return ta.IsTaintedByString(OVERFLOW_ID, 0) || ta.IsTaintedByString(OVERFLOW_ID, 1)
	case vm.ISZERO:
		return ta.IsTaintedByString(OVERFLOW_ID, 0)
	case vm.CALL:
		// handle the value in call
		return ta.IsTaintedByString(OVERFLOW_ID, 0) ||
			ta.IsTaintedByString(OVERFLOW_ID, 2)
	case vm.SSTORE:
		// handle the value being stored
		return ta.IsTaintedByString(OVERFLOW_ID, 1)
	}
	return false
}

func detect_overflow(tracer *BugDetectorTracer, pc uint64, opcode byte, scope tracing.OpContext) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	if isOverflowTaintSource(opcode, scope) {
		// lastCall.taintAnalyzer.AddTaintSource(opcode, pc)
		lastCall.taintAnalyzer.AddTaintSourceByString(OVERFLOW_ID)
	} else if isOverflowTaintSunk(opcode, lastCall.taintAnalyzer) {
		id := fmt.Sprintf("OVERFLOW-%s-%d-%s", lastCall.codeAddress.Hex(), pc, vm.OpCode(opcode).String())
		lastCall.overflowPoints[id] = true
	}
}

func confirm_overflow(tracer *BugDetectorTracer) {
	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	for id := range lastCall.overflowPoints {
		tracer.bugMap.CoverBug(id)
	}
}

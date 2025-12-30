package bugdetector

import (
	"fmt"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	"github.com/crytic/medusa-geth/core/vm"
)

func isUnsafeDelegatecallTaintSourceStack(opcode byte) bool {
	op := vm.OpCode(opcode)
	return op == vm.CALLDATALOAD ||
		op == vm.CALLDATASIZE ||
		op == vm.CALLVALUE ||
		op == vm.GASPRICE ||
		op == vm.ORIGIN ||
		op == vm.CALLER
}

func isUnsafeDelegatecallTaintSourceMemory(opcode byte, scope tracing.OpContext) (bool, uint64, uint64) {

	switch vm.OpCode(opcode) {
	case vm.CALLDATACOPY:
		scopeContext := scope.(*vm.ScopeContext)
		destOffset, _, size := scopeContext.Stack.Back(0), scopeContext.Stack.Back(1), scopeContext.Stack.Back(2)
		start := destOffset.Uint64()
		end := start + size.Uint64()
		return true, start, end
	}
	return false, 0, 0
}

func isTaintedByUnsafeDelegatecall(ta *TaintAnalyzer, stackIndex int) bool {
	return ta.IsTaintedByOpcode(byte(vm.CALLDATALOAD), stackIndex) ||
		ta.IsTaintedByOpcode(byte(vm.CALLDATASIZE), stackIndex) ||
		ta.IsTaintedByOpcode(byte(vm.CALLVALUE), stackIndex) ||
		ta.IsTaintedByOpcode(byte(vm.GASPRICE), stackIndex) ||
		ta.IsTaintedByOpcode(byte(vm.ORIGIN), stackIndex) ||
		ta.IsTaintedByOpcode(byte(vm.CALLDATACOPY), stackIndex)
}

func isUnsafeDelegatecallTaintSunk(ta *TaintAnalyzer) bool {
	return isTaintedByUnsafeDelegatecall(ta, 0) ||
		isTaintedByUnsafeDelegatecall(ta, 1) ||
		isTaintedByUnsafeDelegatecall(ta, 2) ||
		isTaintedByUnsafeDelegatecall(ta, 3)
}

func isUnsafeDelegatecallTaintMemorySunk(ta *TaintAnalyzer, scope tracing.OpContext) bool {
	scopeContext := scope.(*vm.ScopeContext)
	argsOffset := scopeContext.Stack.Back(2).Uint64()
	argsSize := scopeContext.Stack.Back(3).Uint64()

	// fmt.Println(argsOffset, argsOffset+argsSize)

	return ta.IsTantedMemoryByOpcode(byte(vm.CALLDATACOPY), argsOffset, argsOffset+argsSize)
}

func detect_unsafe_delegatecall(tracer *BugDetectorTracer, pc uint64, opcode byte, scope tracing.OpContext) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	isFromAttacker := false
	for _, addr := range tracer.adversarialAddresses {
		if addr == lastCall.from {
			isFromAttacker = true
			break
		}
	}
	if isFromAttacker {
		if isUnsafeDelegatecallTaintSourceStack(opcode) {
			lastCall.taintAnalyzer.AddTaintSourceByOpcode(opcode)
		}
		isSource, start, end := isUnsafeDelegatecallTaintSourceMemory(opcode, scope)
		if isSource {
			lastCall.taintAnalyzer.AddTaintSourceMemoryByOpcode(opcode, start, end)
		}
	}

	if vm.OpCode(opcode) == vm.DELEGATECALL {

		flag := false
		// check if the detegatecall is made to an adversarial address
		isToAdversarialAddress := false
		scopeContext := scope.(*vm.ScopeContext)
		toAddress := common.BigToAddress(scopeContext.Stack.Back(1).ToBig())
		for _, addr := range tracer.adversarialAddresses {
			if addr == toAddress {
				isToAdversarialAddress = true
				break
			}
		}
		flag = isToAdversarialAddress

		// check if the delegatecall is tainted by unsafe sources
		if flag == false {
			if isUnsafeDelegatecallTaintSunk(lastCall.taintAnalyzer) {
				flag = true
			}
			if isUnsafeDelegatecallTaintMemorySunk(lastCall.taintAnalyzer, scope) {
				flag = true
			}
		}

		if flag {
			id := fmt.Sprintf("UNSAFEDELEGATECALL-%s-%d-%s", lastCall.codeAddress, pc, vm.OpCode(opcode).String())
			tracer.bugMap.CoverBug(id)
		}

	}

}

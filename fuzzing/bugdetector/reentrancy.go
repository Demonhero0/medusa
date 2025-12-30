package bugdetector

import (
	"fmt"
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	"github.com/crytic/medusa-geth/core/vm"
)

func isReentrancyTaintSunk(id string, opcode byte, ta *TaintAnalyzer) bool {
	switch vm.OpCode(opcode) {
	case vm.CALL:
		return ta.IsTaintedByString(id, 2) ||
			ta.IsTaintedByString(id, 3) ||
			ta.IsTaintedByString(id, 4)
	case vm.JUMPI:
		return ta.IsTaintedByString(id, 1)
	default:
		return false
	}

}

func isTouchedAdversialAddress(tracer *BugDetectorTracer) {
	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]

	for _, addr := range tracer.adversarialAddresses {
		if lastCall.to == addr {
			lastCall.isTouchedAdversialAddress = true
			return
		}
	}
}

func detect_reentrancy(tracer *BugDetectorTracer, pc uint64, opcode byte, scope tracing.OpContext) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]

	if !lastCall.isContract {
		return
	}

	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	scopeContext := scope.(*vm.ScopeContext)
	switch vm.OpCode(opcode) {
	case vm.SLOAD:
		key := common.BigToHash(scopeContext.Stack.Back(0).ToBig())
		value := tracer.evm.StateDB.GetState(lastCall.to, key)
		ts := TaintStorageSlot{
			opcode: opcode,
			pc:     pc,
			slot:   key,
			value:  value,
		}
		lastCall.taintAnalyzer.AddTaintSource(opcode, pc)
		lastCall.sloadPoints[ts.id()] = ts
	case vm.JUMPI:
		// for the case that the sload value is only used to determine branch
		for id := range lastCall.sloadPoints {
			if isReentrancyTaintSunk(id, opcode, lastCall.taintAnalyzer) {
				jumpId := fmt.Sprintf("%d-%s", pc, vm.OpCode(opcode))
				lastCall.taintedJUMPIPoints[jumpId] = append(lastCall.taintedJUMPIPoints[jumpId], id)
			}
		}

	case vm.CALL:
		gas := scopeContext.Stack.Back(0).ToBig()
		callId := fmt.Sprintf("%d-%s", pc, vm.OpCode(opcode))
		if gas.Cmp(big.NewInt(2300)) == 1 {
			for id := range lastCall.sloadPoints {
				if isReentrancyTaintSunk(id, opcode, lastCall.taintAnalyzer) {
					lastCall.taintedCallPoints[callId] = append(lastCall.taintedCallPoints[callId], id)
				}
			}
			// further serves the call as taint if it is interfered by tainted JUMPI
			for _, sloadIds := range lastCall.taintedJUMPIPoints {
				lastCall.taintedCallPoints[callId] = append(lastCall.taintedCallPoints[callId], sloadIds...)
			}
		}
	case vm.SSTORE:
		if lastCall.isTouchedAdversialAddress {
			key := common.BigToHash(scopeContext.Stack.Back(0).ToBig())
			for callId, sloadIds := range lastCall.taintedCallPoints {
				for _, sloadId := range sloadIds {
					ts := lastCall.sloadPoints[sloadId]
					if key == ts.slot {
						bugId := fmt.Sprintf("REENTRANCY-%s-%s", lastCall.codeAddress, callId)
						tracer.bugMap.CoverBug(bugId)
					}
				}
			}
		}
	}
}

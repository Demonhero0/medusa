package bugdetector

import (
	"fmt"

	"github.com/crytic/medusa-geth/core/vm"
)

func detect_suicidal(tracer *BugDetectorTracer, pc uint64, opcode byte) {

	if vm.OpCode(opcode) == vm.SELFDESTRUCT {
		lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
		id := fmt.Sprintf("SUICIDAL-%s-%d-%s", lastCall.codeAddress.Hex(), pc, vm.OpCode(opcode).String())
		lastCall.selfdestructPoints[id] = true
	}
}

func confirm_suicidal(tracer *BugDetectorTracer) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	for id := range lastCall.selfdestructPoints {
		tracer.bugMap.CoverBug(id)
	}
}

package bugdetector

import (
	"fmt"
	"math/big"
)

func detect_etherleaking(tracer *BugDetectorTracer) {

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]

	lastEther := big.NewInt(0)
	for _, addr := range tracer.adversarialAddresses {
		if lastCall.from == addr {
			return
		}
		b := tracer.evm.StateDB.GetBalance(addr).ToBig()
		lastEther = new(big.Int).Add(lastEther, b)
	}

	if lastEther.Cmp(tracer.originalEther) > 0 {
		id := fmt.Sprintf("ETHERLEAKING-%s", lastCall.from.Hex())
		lastCall.etherleakingPoints[id] = true

	}
}

func confirm_etherleaking(tracer *BugDetectorTracer) {
	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]
	for id := range lastCall.etherleakingPoints {
		tracer.bugMap.CoverBug(id)
	}
}

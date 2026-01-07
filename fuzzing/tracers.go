package fuzzing

import (
	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/bugdetector"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/branchcoverage"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/branchdistance"
	cmpdistance "github.com/crytic/medusa/fuzzing/fitnessmetrics/cmpdistance"
	codecoverage "github.com/crytic/medusa/fuzzing/fitnessmetrics/codecoverage"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/dataflow"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/storagewrite"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/tokenflow"
)

func (fw *FuzzerWorker) attachTracersToChain(initializedChain *chain.TestChain) {

	if fw.fuzzer.config.Fuzzing.UseCodeCoverageTracing() {
		fw.codeCoverageTracer = codecoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.codeCoverageTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseBranchCoverageTracing() {
		// fw.coverageTracer = bracnhcoverage.NewCoverageTracer()
		// initializedChain.AddTracer(fw.coverageTracer.NativeTracer(), true, false)

		fw.branchCoverageTracer = branchcoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.branchCoverageTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseCmpDistanceTracing() {
		fw.cmpDistanceTracer = cmpdistance.NewCmpDistanceTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.cmpDistanceTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseBranchDistanceTracing() {
		fw.branchDistanceTracer = branchdistance.NewBranchDistanceTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.branchDistanceTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseDataflowTracing() {
		fw.dataFlowTracer = dataflow.NewDataflowTracer()
		initializedChain.AddTracer(fw.dataFlowTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseStorageWriteTracing() {
		fw.storageWriteTracer = storagewrite.NewStorageWriteTracer()
		initializedChain.AddTracer(fw.storageWriteTracer.NativeTracer(), true, false)
	}

	if fw.fuzzer.config.Fuzzing.UseTokenflowTracing() {
		fw.tokenflowTracer = tokenflow.NewTokenflowTracer()
		initializedChain.AddTracer(fw.tokenflowTracer.NativeTracer(), true, false)
	}

	// attach bug detector
	if fw.fuzzer.config.Fuzzing.UseBugDetector() {
		fw.bugDetectorTracer = bugdetector.NewBugDetectorTracer(FuzzHelperContractAddress, &fw.fuzzer.config.Fuzzing.BugDetectionConfig)
		initializedChain.AddTracer(fw.bugDetectorTracer.NativeTracer(), true, false)

		// set original ether for ether leaking
		if fw.fuzzer.config.Fuzzing.BugDetectionConfig.EtherLeaking {
			fw.bugDetectorTracer.SetOriginalEther(fw.fuzzer.config.Fuzzing.SenderAddressBalances)
		}

		if fw.fuzzer.config.Fuzzing.BugDetectionConfig.EtherLeaking || fw.fuzzer.config.Fuzzing.BugDetectionConfig.UnsafeDelegateCall {
			var ads []common.Address
			for _, addr := range fw.fuzzer.config.Fuzzing.SenderAddresses {
				ads = append(ads, common.HexToAddress(addr))
			}
			if FuzzHelperContractAddress != common.HexToAddress("0x") {
				ads = append(ads, FuzzHelperContractAddress)
			}

			fw.bugDetectorTracer.SetAdversarialAddresses(ads)
		}
	}

	// debug: tracing execution trace
	fw.executionTracer = executiontracer.NewExecutionTracer(fw.fuzzer.contractDefinitions, initializedChain, config.VeryVeryVerbose)
	initializedChain.AddTracer(fw.executionTracer.NativeTracer(), true, false)
}

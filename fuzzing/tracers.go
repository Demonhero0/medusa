package fuzzing

import (
	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/bugdetector"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/branchcoverage"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/branchdistance"
	cmpdistance "github.com/crytic/medusa/fuzzing/fitnessmetrics/cmpdistance"
	codecoverage "github.com/crytic/medusa/fuzzing/fitnessmetrics/codecoverage"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/dataflow"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/storagewrite"
	"github.com/crytic/medusa/fuzzing/fitnessmetrics/tokenflow"
)

func (fw *FuzzerWorker) attachTracersToChain(initializedChain *chain.TestChain) {
	// attach fitness metric tracers

	// code coverage tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.CodeCoverageEnabled {
		fw.codeCoverageTracer = codecoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.codeCoverageTracer.NativeTracer(), true, false)
	}

	// branch coverage tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.BranchCoverageEnabled {
		fw.branchCoverageTracer = branchcoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.branchCoverageTracer.NativeTracer(), true, false)
	}

	// cmp distance tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.CmpDistanceEnabled {
		fw.cmpDistanceTracer = cmpdistance.NewCmpDistanceTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.cmpDistanceTracer.NativeTracer(), true, false)
	}

	// branch distance tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.BranchDistanceEnabled {
		fw.branchDistanceTracer = branchdistance.NewBranchDistanceTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.branchDistanceTracer.NativeTracer(), true, false)
	}

	// data flow tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.DataflowEnabled {
		fw.dataFlowTracer = dataflow.NewDataflowTracer()
		initializedChain.AddTracer(fw.dataFlowTracer.NativeTracer(), true, false)
	}

	// storage write tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.StorageWriteEnabled {
		fw.storageWriteTracer = storagewrite.NewStorageWriteTracer()
		initializedChain.AddTracer(fw.storageWriteTracer.NativeTracer(), true, false)
	}

	// token flow tracer
	if fw.fuzzer.config.Fuzzing.FitnessMetricConfig.TokenflowEnabled {
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
	// fw.executionTracer = executiontracer.NewExecutionTracer(fw.fuzzer.contractDefinitions, initializedChain, config.VeryVeryVerbose)
	// initializedChain.AddTracer(fw.executionTracer.NativeTracer(), true, false)

	// for fair comparison, we need to attach the indicator tracers solely

	// code coverage tracer
	if fw.fuzzer.config.Fuzzing.MetricRecordConfig.CodeCoverageEnabled {
		fw.codeCoverageIndicatorTracer = codecoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.codeCoverageIndicatorTracer.NativeTracer(), true, false)
	}

	// branch coverage tracer
	if fw.fuzzer.config.Fuzzing.MetricRecordConfig.BranchCoverageEnabled {
		fw.branchCoverageIndicatorTracer = branchcoverage.NewCoverageTracer(fw.fuzzer.contractDefinitions)
		initializedChain.AddTracer(fw.branchCoverageIndicatorTracer.NativeTracer(), true, false)
	}

	// data flow tracer
	if fw.fuzzer.config.Fuzzing.MetricRecordConfig.DataflowEnabled {
		fw.dataFlowIndicatorTracer = dataflow.NewDataflowTracer()
		initializedChain.AddTracer(fw.dataFlowIndicatorTracer.NativeTracer(), true, false)
	}

	// storage write tracer
	if fw.fuzzer.config.Fuzzing.MetricRecordConfig.StorageWriteEnabled {
		fw.storageWriteIndicatorTracer = storagewrite.NewStorageWriteTracer()
		initializedChain.AddTracer(fw.storageWriteIndicatorTracer.NativeTracer(), true, false)
	}

	// token flow tracer
	if fw.fuzzer.config.Fuzzing.MetricRecordConfig.TokenflowEnabled {
		fw.tokenflowIndicatorTracer = tokenflow.NewTokenflowTracer()
		initializedChain.AddTracer(fw.tokenflowIndicatorTracer.NativeTracer(), true, false)
	}
}

package fuzzing

import (
	"github.com/crytic/medusa/chain"
	bracnhcoverage "github.com/crytic/medusa/fuzzing/coverage"
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
		fw.coverageTracer = bracnhcoverage.NewCoverageTracer()
		initializedChain.AddTracer(fw.coverageTracer.NativeTracer(), true, false)
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

	// debug: tracing execution trace
	// fw.executionTracer = executiontracer.NewExecutionTracer(fw.fuzzer.contractDefinitions, initializedChain, config.VeryVeryVerbose)
	// initializedChain.AddTracer(fw.executionTracer.NativeTracer(), true, false)
}

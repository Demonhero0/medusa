package fuzzing

import (
	"math/big"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	branchcoverage "github.com/crytic/medusa/fuzzing/fitnessmetrics/branchcoverage"
	codecoverage "github.com/crytic/medusa/fuzzing/fitnessmetrics/codecoverage"
	dataflow "github.com/crytic/medusa/fuzzing/fitnessmetrics/dataflow"
	storagewrite "github.com/crytic/medusa/fuzzing/fitnessmetrics/storagewrite"
	tokenflow "github.com/crytic/medusa/fuzzing/fitnessmetrics/tokenflow"
	"github.com/crytic/medusa/fuzzing/reverts"
)

// FuzzerMetrics represents a struct tracking metrics for a Fuzzer run.
type FuzzerMetrics struct {
	// workerMetrics describes the metrics for each individual worker. This expands as needed and some slots may be nil
	// while workers are initializing, as it corresponds to the indexes in Fuzzer.workers.
	workerMetrics []fuzzerWorkerMetrics

	// indicator tracers are used to record metrics during fuzzing.
	//codeCoverageMaps describes the total instructions being executed across all corpus call sequences
	codeCoverageMaps *codecoverage.CoverageMaps

	// branchCoverageMaps describes the total branches known to be achieved across all corpus call sequences
	branchCoverageMaps *branchcoverage.CoverageMaps

	// dataflowMaps describes the triggered dataflw
	dataflowMaps *dataflow.DataflowSet

	// storageWriteMaps describes the storage slots being written
	storageWriteMaps *storagewrite.StorageWriteSet

	// tokenflowMaps describes the token flow being triggered
	tokenflowMaps *tokenflow.TokenflowSet

	// fuzzingConfig describes the configuration for fuzzing.
	fuzzingConfig *config.FuzzingConfig
}

// fuzzerWorkerMetrics represents metrics for a single FuzzerWorker instance.
type fuzzerWorkerMetrics struct {
	// sequencesTested is the amount of sequences of transactions which tests were run against.
	sequencesTested *big.Int

	// failedSequences is the amount of sequences of transactions which tests failed.
	failedSequences *big.Int

	// callsTested is the amount of transactions/calls the fuzzer executed and ran tests against.
	callsTested *big.Int

	// revertMetricsChan is the channel for sending revert metrics updates to the revert reporter.
	// Note that the channel can be nil here if revert metrics are not enabled
	revertMetricsChan chan reverts.RevertMetricsUpdate

	// gasUsed is the amount of gas the fuzzer executed and ran tests against.
	gasUsed *big.Int

	// workerStartupCount is the amount of times the worker was generated, or re-generated for this index.
	workerStartupCount *big.Int

	// shrinking indicates whether the fuzzer worker is currently shrinking.
	shrinking bool
}

// newFuzzerMetrics obtains a new FuzzerMetrics struct for a given number of workers specified by workerCount.
// An optional channel for sending revert metrics updates to the revert reporter is also provided.
// Returns the new FuzzerMetrics object.
func newFuzzerMetrics(workerCount int, revertMetricsCh chan reverts.RevertMetricsUpdate, fuzzingConfig *config.FuzzingConfig) *FuzzerMetrics {
	// Create a new metrics struct and return it with as many slots as required.
	metrics := FuzzerMetrics{
		workerMetrics: make([]fuzzerWorkerMetrics, workerCount),
	}
	for i := 0; i < len(metrics.workerMetrics); i++ {
		metrics.workerMetrics[i].sequencesTested = big.NewInt(0)
		metrics.workerMetrics[i].failedSequences = big.NewInt(0)
		metrics.workerMetrics[i].callsTested = big.NewInt(0)
		metrics.workerMetrics[i].workerStartupCount = big.NewInt(0)
		metrics.workerMetrics[i].gasUsed = big.NewInt(0)
		metrics.workerMetrics[i].revertMetricsChan = revertMetricsCh

	}

	// init indicators maps
	metrics.fuzzingConfig = fuzzingConfig
	metrics.codeCoverageMaps = codecoverage.NewCoverageMaps()
	metrics.branchCoverageMaps = branchcoverage.NewCoverageMaps()
	metrics.dataflowMaps = dataflow.NewDataflowSet()
	metrics.storageWriteMaps = storagewrite.NewStorageWriteSet()
	metrics.tokenflowMaps = tokenflow.NewTokenflowSet()
	return &metrics
}

// FailedSequences returns the number of sequences that led to failures across all workers
func (m *FuzzerMetrics) FailedSequences() *big.Int {
	failedSequences := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		failedSequences.Add(failedSequences, workerMetrics.failedSequences)
	}
	return failedSequences
}

// SequencesTested returns the amount of sequences of transactions the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) SequencesTested() *big.Int {
	sequencesTested := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		sequencesTested.Add(sequencesTested, workerMetrics.sequencesTested)
	}
	return sequencesTested
}

// CallsTested returns the amount of transactions/calls the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) CallsTested() *big.Int {
	transactionsTested := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		transactionsTested.Add(transactionsTested, workerMetrics.callsTested)
	}
	return transactionsTested
}

func (m *FuzzerMetrics) GasUsed() *big.Int {
	gasUsed := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		gasUsed.Add(gasUsed, workerMetrics.gasUsed)
	}
	return gasUsed
}

// WorkerStartupCount describes the amount of times the worker was spawned for this index. Workers are periodically
// reset.
func (m *FuzzerMetrics) WorkerStartupCount() *big.Int {
	workerStartupCount := big.NewInt(0)
	for _, workerMetrics := range m.workerMetrics {
		workerStartupCount.Add(workerStartupCount, workerMetrics.workerStartupCount)
	}
	return workerStartupCount
}

// WorkersShrinkingCount returns the amount of workers currently performing shrinking operations.
func (m *FuzzerMetrics) WorkersShrinkingCount() uint64 {
	shrinkingCount := uint64(0)
	for _, workerMetrics := range m.workerMetrics {
		if workerMetrics.shrinking {
			shrinkingCount++
		}
	}
	return shrinkingCount
}

// updateRevertMetrics updates the revert metrics for the fuzzer worker based on the call sequence element.
func (m *fuzzerWorkerMetrics) updateRevertMetrics(callSequenceElement *calls.CallSequenceElement) {
	// The channel will be nil if revert metrics are not enabled
	if callSequenceElement == nil || m.revertMetricsChan == nil {
		return
	}

	// Send the revert metrics update to the revert reporter
	m.revertMetricsChan <- reverts.RevertMetricsUpdate{
		ContractName:    callSequenceElement.Contract.Name(),
		FunctionName:    callSequenceElement.Call.DataAbiValues.Method.Name,
		ExecutionResult: callSequenceElement.ChainReference.MessageResults().ExecutionResult,
	}
}

func (m *FuzzerMetrics) updateIndicators(lastCall *calls.CallSequenceElement) error {

	lastCallChainReference := lastCall.ChainReference
	lastMessageResult := lastCallChainReference.Block.MessageResults[lastCallChainReference.TransactionIndex]

	if m.fuzzingConfig.MetricRecordConfig.CodeCoverageEnabled {
		codeCoverageMaps := codecoverage.GetCoverageTracerResults(lastMessageResult)
		_, err := m.codeCoverageMaps.Update(codeCoverageMaps)
		if err != nil {
			return err
		}
	}

	if m.fuzzingConfig.MetricRecordConfig.BranchCoverageEnabled {
		branchCoverageMaps := branchcoverage.GetCoverageTracerResults(lastMessageResult)
		_, err := m.branchCoverageMaps.Update(branchCoverageMaps)
		if err != nil {
			return err
		}
	}

	if m.fuzzingConfig.MetricRecordConfig.DataflowEnabled {
		dataflowMaps := dataflow.GetDataflowTracerResults(lastMessageResult)
		_, err := m.dataflowMaps.Update(dataflowMaps)
		if err != nil {
			return err
		}
	}

	if m.fuzzingConfig.MetricRecordConfig.StorageWriteEnabled {
		storageWriteMaps := storagewrite.GetStorageWriteTracerResults(lastMessageResult)
		_, err := m.storageWriteMaps.Update(storageWriteMaps)
		if err != nil {
			return err
		}
	}

	if m.fuzzingConfig.MetricRecordConfig.TokenflowEnabled {
		tokenflowMaps := tokenflow.GetTokenflowTracerResults(lastMessageResult)
		_, err := m.tokenflowMaps.Update(tokenflowMaps)
		if err != nil {
			return err
		}
	}
	return nil
}

// CoverageMaps exposes coverage details for all call sequences known to the corpus.
func (m *FuzzerMetrics) CodeCoverageMaps() *codecoverage.CoverageMaps {
	return m.codeCoverageMaps
}

func (m *FuzzerMetrics) BranchCoverageMaps() *branchcoverage.CoverageMaps {
	return m.branchCoverageMaps
}

func (m *FuzzerMetrics) DataflowSet() *dataflow.DataflowSet {
	return m.dataflowMaps
}

func (m *FuzzerMetrics) StorageWriteMaps() *storagewrite.StorageWriteSet {
	return m.storageWriteMaps
}

func (m *FuzzerMetrics) TokenflowMaps() *tokenflow.TokenflowSet {
	return m.tokenflowMaps
}

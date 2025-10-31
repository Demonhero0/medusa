package fuzzing

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa/chain"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/executiontracer"

	"github.com/crytic/medusa-geth/common"
)

type ContractInfo struct {
	Address          string `json:"address"`
	CompilerVersion  string `json:"compilerVersion"`
	ContractName     string `json:"contractName"`
	ContractPath     string `json:"contractPath"`
	MainContractPath string `json:"mainContractPath"`
	Abi              string `json:"abi"`
	Proxy            bool   `json:"Proxy"`
	Implementation   string `json:"Implementation"`
}

func (f *Fuzzer) loadOnChainContract(targetAddress string) (*compilationTypes.CompiledContract, error) {
	targetAddress = strings.ToLower(targetAddress)
	contractAbiStr, err := getAbiStr(targetAddress)
	if err != nil {
		return nil, err
	}

	contractAbi, err := abi.JSON(strings.NewReader(contractAbiStr))
	if err != nil {
		return nil, fmt.Errorf("ABI Parser error: %v, contractInfo: %#v", err, contractAbi)
	}

	contract := compilationTypes.CompiledContract{
		Abi: contractAbi,
	}
	return &contract, nil
}

func getAbiStr(address string) (string, error) {
	abiFilePath := "abi.json"
	content, err := os.ReadFile(abiFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read abi file %s: %w", abiFilePath, err)
	}

	var allAbis map[string][]string
	if err := json.Unmarshal(content, &allAbis); err != nil {
		return "", fmt.Errorf("failed to unmarshal abi json: %w", err)
	}

	signatures, ok := allAbis[strings.ToLower(address)]
	if !ok {
		return "", fmt.Errorf("no ABI found for address %s in %s", address, abiFilePath)
	}

	var methodAbis []string
	for _, sig := range signatures {
		parts := strings.SplitN(sig, "(", 2)
		if len(parts) < 2 {
			continue // Invalid signature format
		}
		name := parts[0]
		inputTypesStr := strings.TrimSuffix(parts[1], ")")

		var inputTypes []string
		if inputTypesStr != "" {
			inputTypes = strings.Split(inputTypesStr, ",")
		}

		var inputsJson []string
		for i, inputType := range inputTypes {
			inputsJson = append(inputsJson, fmt.Sprintf(`{"name": "arg%d", "type": "%s"}`, i, inputType))
		}

		// Assume payable to allow fuzzing with value transfers.
		// Assume no outputs for simplicity.
		methodAbi := fmt.Sprintf(
			`{"type": "function", "name": "%s", "inputs": [%s], "outputs": [], "stateMutability": "payable"}`,
			name,
			strings.Join(inputsJson, ","),
		)
		methodAbis = append(methodAbis, methodAbi)
	}

	return "[" + strings.Join(methodAbis, ",") + "]", nil
}

func chainSetupOnChain(fuzzer *Fuzzer, testChain *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
	fuzzer.logger.Info("Setting up test chain for on-chain target contracts")

	for _, contractDefinition := range fuzzer.contractDefinitions {
		contractAddress := common.HexToAddress(contractDefinition.Name())
		contractDefinition.CompiledContract().RuntimeBytecode = testChain.State().GetCode(contractAddress)
		if len(contractDefinition.CompiledContract().RuntimeBytecode) == 0 {
			return nil, fmt.Errorf("failed to get code for on-chain target contract %s", contractAddress.Hex())
		}
	}
	return nil, nil
}

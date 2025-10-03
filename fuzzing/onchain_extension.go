package fuzzing

import (
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
	address = strings.ToLower(address)
	path := fmt.Sprintf("abis/%s.json", address)
	isExistFile := true
	if _, err := os.Stat(path); os.IsNotExist(err) {
		isExistFile = false
	} else if err != nil {
		isExistFile = false
	}

	// existing file
	if isExistFile {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(content), err
	} else {
		return "", fmt.Errorf("the contract info file %s not exist", path)
	}
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

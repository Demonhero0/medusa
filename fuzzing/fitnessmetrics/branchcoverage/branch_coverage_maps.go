package branchcoverage

import (
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/crypto"
	compilationTypes "github.com/crytic/medusa/compilation/types"
)

// CoverageMaps represents a data structure used to identify branch coverage of various smart contracts
// across a transaction or multiple transactions.
type CoverageMaps struct {
	// maps represents a structure used to track every ContractCoverageMap by a given deployed address/lookup hash.
	maps map[common.Hash]map[common.Address]*ContractCoverageMap

	// cachedCodeAddress represents the last code address which coverage was updated for. This is used to prevent an
	// expensive lookup in maps. If cachedCodeHash does not match the current code address for which we are updating
	// coverage for, it, along with other cache variables are updated.
	cachedCodeAddress common.Address

	// cachedCodeHash represents the last lookup hash which coverage was updated for. This is used to prevent an
	// expensive lookup in maps. If cachedCodeHash does not match the current code hash which we are updating
	// coverage for, it, along with other cache variables are updated.
	cachedCodeHash common.Hash

	// cachedMap represents the last coverage map which was updated. If the coverage to update resides at the
	// cachedCodeAddress and matches the cachedCodeHash, then this map is used to avoid an expensive lookup into maps.
	cachedMap *ContractCoverageMap

	// lock is a read-write mutex to offer concurrent thread safety for map accesses.
	lock sync.RWMutex
}

func (cm *CoverageMaps) TotalBranchCoverage(targetAddresses []common.Address) (int, int) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	coveredBranchSize := 0
	totalBranchSize := 0
	for i := range cm.maps {
		if len(targetAddresses) > 0 {
			for _, j := range targetAddresses {
				ccm, exists := cm.maps[i][j]
				if !exists {
					continue
				}
				c, t := ccm.getCoverageRate()
				coveredBranchSize += c
				totalBranchSize += t
			}
		} else {
			for _, j := range cm.maps[i] {
				c, t := j.getCoverageRate()
				coveredBranchSize += c
				totalBranchSize += t
			}
		}
	}
	return coveredBranchSize, totalBranchSize
}

// NewCoverageMaps initializes a new CoverageMaps object.
func NewCoverageMaps() *CoverageMaps {
	maps := &CoverageMaps{}
	maps.Reset()
	return maps
}

// Reset clears the coverage state for the CoverageMaps.
func (cm *CoverageMaps) Reset() {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	cm.maps = make(map[common.Hash]map[common.Address]*ContractCoverageMap)
	cm.cachedCodeAddress = common.Address{}
	cm.cachedCodeHash = common.Hash{}
	cm.cachedMap = nil
}

// getContractCoverageMapHash obtain the hash used to look up a given contract's ContractCoverageMap.
// If this is init bytecode, metadata and abi arguments will attempt to be stripped, then a hash is computed.
// If this is runtime bytecode, the metadata ipfs/swarm hash will be used if available, otherwise the bytecode
// is hashed.
// Returns the resulting lookup hash.
func getContractCoverageMapHash(bytecode []byte, init bool) common.Hash {
	// If available, the metadata code hash should be unique and reliable to use above all (for runtime bytecode).
	if !init {
		metadata := compilationTypes.ExtractContractMetadata(bytecode)
		if metadata != nil {
			metadataHash := metadata.ExtractBytecodeHash()
			if metadataHash != nil {
				return common.BytesToHash(metadataHash)
			}
		}
	}

	// Otherwise, we use the hash of the bytecode after attempting to strip metadata (and constructor args).
	strippedBytecode := compilationTypes.RemoveContractMetadata(bytecode)
	return crypto.Keccak256Hash(strippedBytecode)
}

// GetContractCoverageMap obtains a total coverage map representing coverage for the provided bytecode.
// If the provided bytecode could not find coverage maps, nil is returned.
// Returns the total coverage map, or an error if one occurs.
func (cm *CoverageMaps) GetContractCoverageMap(bytecode []byte, init bool) (*ContractCoverageMap, error) {
	// Obtain the lookup hash
	hash := getContractCoverageMapHash(bytecode, init)

	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	// Loop through all coverage maps for this hash and collect our total coverage.
	if coverageByAddresses, ok := cm.maps[hash]; ok {
		totalCoverage := newContractCoverageMap()
		for _, coverage := range coverageByAddresses {
			_, err := totalCoverage.update(coverage)
			if err != nil {
				return nil, err
			}
		}
		return totalCoverage, nil
	} else {
		return nil, nil
	}
}

// Update updates the current coverage maps with the provided ones.
// Returns two booleans indicating whether successful or reverted coverage changed, or an error if one occurred.
func (cm *CoverageMaps) Update(coverageMaps *CoverageMaps) (bool, error) {
	// If our maps provided are nil, do nothing
	if coverageMaps == nil {
		return false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.lock.Lock()
	defer cm.lock.Unlock()

	// Create a boolean indicating whether we achieved new coverage
	successCoverageChanged := false

	// Loop for each coverage map provided
	for codeHash, mapsByAddressToMerge := range coverageMaps.maps {
		for codeAddress, coverageMapToMerge := range mapsByAddressToMerge {
			// If a coverage map lookup for this code hash doesn't exist, create the mapping.
			mapsByAddress, codeHashExists := cm.maps[codeHash]
			if !codeHashExists {
				mapsByAddress = make(map[common.Address]*ContractCoverageMap)
				cm.maps[codeHash] = mapsByAddress
			}

			// If a coverage map for this address already exists in our current mapping, update it with the one
			// to merge. If it doesn't exist, set it to the one to merge.
			if existingCoverageMap, codeAddressExists := mapsByAddress[codeAddress]; codeAddressExists {
				sChanged, err := existingCoverageMap.update(coverageMapToMerge)
				successCoverageChanged = successCoverageChanged || sChanged
				if err != nil {
					return successCoverageChanged, err
				}
			} else {
				mapsByAddress[codeAddress] = coverageMapToMerge
				successCoverageChanged = coverageMapToMerge.successfulCoverage != nil
			}
		}
	}

	// Return our results
	return successCoverageChanged, nil
}

// SetAt sets the coverage state of a given path of a branch instruction within code coverage data.
func (cm *CoverageMaps) SetAt(codeAddress common.Address, codeLookupHash common.Hash, branchSize, id int) (bool, error) {
	// If the branch size is zero, do nothing
	if branchSize == 0 {
		return false, nil
	}

	cm.lock.Lock()
	defer cm.lock.Unlock()

	// Define variables used to update coverage maps and track changes.
	var (
		addedNewMap  bool
		changedInMap bool
		coverageMap  *ContractCoverageMap
		err          error
	)

	// Try to obtain a coverage map from our cache
	if cm.cachedMap != nil && cm.cachedCodeAddress == codeAddress && cm.cachedCodeHash == codeLookupHash {
		coverageMap = cm.cachedMap
	} else {
		// If a coverage map lookup for this code hash doesn't exist, create the mapping.
		mapsByCodeAddress, codeHashExists := cm.maps[codeLookupHash]
		if !codeHashExists {
			mapsByCodeAddress = make(map[common.Address]*ContractCoverageMap)
			cm.maps[codeLookupHash] = mapsByCodeAddress
		}

		// Obtain the coverage map for this code address if it already exists. If it does not, create a new one.
		if existingCoverageMap, codeAddressExists := mapsByCodeAddress[codeAddress]; codeAddressExists {
			coverageMap = existingCoverageMap
		} else {
			coverageMap = newContractCoverageMap()
			cm.maps[codeLookupHash][codeAddress] = coverageMap
			addedNewMap = true
		}

		// Set our cached variables for faster coverage setting next time this method is called.
		cm.cachedMap = coverageMap
		cm.cachedCodeHash = codeLookupHash
		cm.cachedCodeAddress = codeAddress
	}

	// Set our coverage in the map and return our change state
	changedInMap, err = coverageMap.setCoveredAt(branchSize, id)
	return addedNewMap || changedInMap, err
}

// RevertAll sets all coverage in the coverage map as reverted coverage. Reverted coverage is updated with successful
// coverage, the successful coverage is cleared.
// Returns a boolean indicating whether reverted coverage increased, and an error if one occurred.
func (cm *CoverageMaps) RevertAll() {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.lock.Lock()
	defer cm.lock.Unlock()

	// Loop for each coverage map provided
	for _, mapsByAddressToMerge := range cm.maps {
		for _, contractCoverageMap := range mapsByAddressToMerge {

			// Clear our successful coverage, as these maps were marked as reverted.
			contractCoverageMap.successfulCoverage.Reset()
		}
	}
}

// ContractCoverageMap represents a data structure used to identify branch coverage of a contract.
type ContractCoverageMap struct {
	// successfulCoverage represents coverage for the contract bytecode, which did not encounter a revert and was
	// deemed successful.
	successfulCoverage *CoverageMapBranchData
}

// newContractCoverageMap creates and returns a new ContractCoverageMap.
func newContractCoverageMap() *ContractCoverageMap {
	return &ContractCoverageMap{
		successfulCoverage: &CoverageMapBranchData{},
	}
}

// update creates updates the current ContractCoverageMap with the provided one.
// Returns two booleans indicating whether successful or reverted coverage changed, or an error if one was encountered.
func (cm *ContractCoverageMap) update(coverageMap *ContractCoverageMap) (bool, error) {
	// Update our success coverage data
	successfulCoverageChanged, err := cm.successfulCoverage.update(coverageMap.successfulCoverage)
	if err != nil {
		return false, err
	}

	return successfulCoverageChanged, nil
}

// setCoveredAt sets the coverage state at a given branch within a ContractCoverageMap used for
// "successful" coverage (non-reverted).
// Returns a boolean indicating whether new coverage was achieved, or an error if one occurred.
func (cm *ContractCoverageMap) setCoveredAt(branchSize, id int) (bool, error) {
	// Set our coverage data for the successful branch.
	return cm.successfulCoverage.setCoveredAt(branchSize, id)
}

// getCoverageRate returns the covered branch size and the total branch size of the contract.
func (cm *ContractCoverageMap) getCoverageRate() (int, int) {
	return cm.successfulCoverage.getCoverageRate()
}

func (cm *ContractCoverageMap) getCoverageByteMap() []byte {
	return cm.successfulCoverage.executedFlags
}

// CoverageMapBranchData represents a data structure used to identify branch coverage of some init
// or runtime bytecode.
type CoverageMapBranchData struct {
	executedFlags []byte
}

// Reset resets the branch coverage map data to be empty.
func (cm *CoverageMapBranchData) Reset() {
	cm.executedFlags = nil
}

// update creates updates the current CoverageMapBranchData with the provided one.
// Returns a boolean indicating whether new coverage was achieved, or an error if one was encountered.
func (cm *CoverageMapBranchData) update(coverageMap *CoverageMapBranchData) (bool, error) {
	// If the coverage map execution data provided is nil, exit early
	if coverageMap.executedFlags == nil {
		return false, nil
	}

	// If the current map has no execution data, simply set it to the provided one.
	if cm.executedFlags == nil {
		cm.executedFlags = coverageMap.executedFlags
		return true, nil
	}

	// Update each byte which represents a branch which was covered.
	changed := false
	for i := 0; i < len(cm.executedFlags) && i < len(coverageMap.executedFlags); i++ {
		if cm.executedFlags[i] == 0 && coverageMap.executedFlags[i] != 0 {
			cm.executedFlags[i] = 1
			changed = true
		}
	}
	return changed, nil
}

// setCoveredAt sets the coverage state at a given branch id within a CoverageMapBlockData.
// Returns a boolean indicating whether new coverage was achieved, or an error if one occurred.
func (cm *CoverageMapBranchData) setCoveredAt(branchSize, id int) (bool, error) {
	// If the execution flags don't exist, create them for this code size.
	if cm.executedFlags == nil {
		cm.executedFlags = make([]byte, branchSize)
	}

	// If our program counter is in range, determine if we achieved new coverage for the first time, and update it.
	if id < len(cm.executedFlags) {
		if cm.executedFlags[id] == 0 {
			cm.executedFlags[id] = 1
			return true, nil
		}
		return false, nil
	}

	// Since it is possible that the program counter is larger than the code size (e.g., malformed bytecode), we will
	// simply return false with no error
	return false, nil
}

func (cm *CoverageMapBranchData) getCoverageRate() (int, int) {
	coveredBranchSize := 0
	for _, v := range cm.executedFlags {
		if v != 0 {
			coveredBranchSize++
		}
	}
	return coveredBranchSize, len(cm.executedFlags)
}

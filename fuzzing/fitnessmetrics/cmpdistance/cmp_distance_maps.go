package cmpdistance

import (
	"fmt"
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/crypto"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/holiman/uint256"
)

// CmpDistanceMaps represents a data structure used to identify branch distance of various smart contracts
// across a transaction or multiple transactions.
type CmpDistanceMaps struct {
	// maps represents a structure used to track every ContractCoverageMap by a given deployed address/lookup hash.
	maps map[common.Hash]map[common.Address]*ContractCmpDistanceMap

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
	cachedMap *ContractCmpDistanceMap

	// updateLock is a lock to offer concurrent thread safety for map accesses.
	updateLock sync.Mutex
}

func (cm *CmpDistanceMaps) TotalCoveredCmpNum(includeReverted bool, targetAddresses []common.Address) int {
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	coveredCmpSize := 0
	for i := range cm.maps {
		if len(targetAddresses) > 0 {
			for _, j := range targetAddresses {
				ccm, exists := cm.maps[i][j]
				if !exists {
					continue
				}
				c := ccm.getCoveredCmpNum(includeReverted)
				coveredCmpSize += c
			}
		} else {
			for _, j := range cm.maps[i] {
				c := j.getCoveredCmpNum(includeReverted)
				coveredCmpSize += c
			}
		}
	}
	return coveredCmpSize
}

func (cm *CmpDistanceMaps) ShowDistance() {
	for i := range cm.maps {
		for j := range cm.maps[i] {
			fmt.Println(i, j, cm.maps[i][j].distanceMap.distance)
		}
	}
}

// NewCmpDistanceMaps initializes a new CmpDistanceMaps object.
func NewCmpDistanceMaps() *CmpDistanceMaps {
	maps := &CmpDistanceMaps{}
	maps.Reset()
	return maps
}

// Reset clears the coverage state for the CmpDistanceMaps.
func (cm *CmpDistanceMaps) Reset() {
	cm.maps = make(map[common.Hash]map[common.Address]*ContractCmpDistanceMap)
	cm.cachedCodeAddress = common.Address{}
	cm.cachedCodeHash = common.Hash{}
	cm.cachedMap = nil
}

// getContractCmpDistanceMapHash obtain the hash used to look up a given contract's ContractCmpDistanceMap.
// If this is init bytecode, metadata and abi arguments will attempt to be stripped, then a hash is computed.
// If this is runtime bytecode, the metadata ipfs/swarm hash will be used if available, otherwise the bytecode
// is hashed.
// Returns the resulting lookup hash.
func getContractCmpDistanceMapHash(bytecode []byte, init bool) common.Hash {
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

// GetContractDistanceDistanceMap obtains a total branch distance map representing branch distance for the provided bytecode.
// If the provided bytecode could not find branch maps, nil is returned.
// Returns the total branch map, or an error if one occurs.
func (cm *CmpDistanceMaps) GetContractDistanceDistanceMap(bytecode []byte, init bool) (*ContractCmpDistanceMap, error) {
	// Obtain the lookup hash
	hash := getContractCmpDistanceMapHash(bytecode, init)

	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Loop through all coverage maps for this hash and collect our total coverage.
	if distanceByAddresses, ok := cm.maps[hash]; ok {
		totalDistance := newContractCmpDistanceMap()
		for _, coverage := range distanceByAddresses {
			_, err := totalDistance.update(coverage)
			if err != nil {
				return nil, err
			}
		}
		return totalDistance, nil
	} else {
		return nil, nil
	}
}

// Update updates the current distance maps with the provided ones.
// Returns two booleans indicating whether successful or reverted coverage changed, or an error if one occurred.
func (cm *CmpDistanceMaps) Update(coverageMaps *CmpDistanceMaps) (bool, error) {
	// If our maps provided are nil, do nothing
	if coverageMaps == nil {
		return false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Create a boolean indicating whether we achieved new coverage
	distanceChanged := false

	// Loop for each coverage map provided
	for codeHash, mapsByAddressToMerge := range coverageMaps.maps {
		for codeAddress, coverageMapToMerge := range mapsByAddressToMerge {
			// If a coverage map lookup for this code hash doesn't exist, create the mapping.
			mapsByAddress, codeHashExists := cm.maps[codeHash]
			if !codeHashExists {
				mapsByAddress = make(map[common.Address]*ContractCmpDistanceMap)
				cm.maps[codeHash] = mapsByAddress
			}

			// If a coverage map for this address already exists in our current mapping, update it with the one
			// to merge. If it doesn't exist, set it to the one to merge.
			if existingCoverageMap, codeAddressExists := mapsByAddress[codeAddress]; codeAddressExists {
				changed, err := existingCoverageMap.update(coverageMapToMerge)
				distanceChanged = distanceChanged || changed
				if err != nil {
					return distanceChanged, err
				}
			} else {
				mapsByAddress[codeAddress] = coverageMapToMerge
				distanceChanged = coverageMapToMerge.distanceMap != nil
			}
		}
	}

	// Return our results
	return distanceChanged, nil
}

// SetAt sets the coverage state of a given path of a branch instruction within code coverage data.
func (cm *CmpDistanceMaps) SetAt(codeAddress common.Address, codeLookupHash common.Hash, id uint64, distance *uint256.Int) (bool, error) {

	// Define variables used to update coverage maps and track changes.
	var (
		addedNewMap    bool
		changedInMap   bool
		cmpDistanceMap *ContractCmpDistanceMap
		err            error
	)

	// Try to obtain a ditance map from our cache
	if cm.cachedMap != nil && cm.cachedCodeAddress == codeAddress && cm.cachedCodeHash == codeLookupHash {
		cmpDistanceMap = cm.cachedMap
	} else {
		// If a coverage map lookup for this code hash doesn't exist, create the mapping.
		mapsByCodeAddress, codeHashExists := cm.maps[codeLookupHash]
		if !codeHashExists {
			mapsByCodeAddress = make(map[common.Address]*ContractCmpDistanceMap)
			cm.maps[codeLookupHash] = mapsByCodeAddress
		}

		// Obtain the distance map for this code address if it already exists. If it does not, create a new one.
		if existingCoverageMap, codeAddressExists := mapsByCodeAddress[codeAddress]; codeAddressExists {
			cmpDistanceMap = existingCoverageMap
		} else {
			cmpDistanceMap = newContractCmpDistanceMap()
			cm.maps[codeLookupHash][codeAddress] = cmpDistanceMap
			addedNewMap = true
		}

		// Set our cached variables for faster coverage setting next time this method is called.
		cm.cachedMap = cmpDistanceMap
		cm.cachedCodeHash = codeLookupHash
		cm.cachedCodeAddress = codeAddress
	}

	// Set our coverage in the map and return our change state
	changedInMap, err = cmpDistanceMap.setDistanceAt(id, distance)
	return addedNewMap || changedInMap, err
}

// RevertAll sets all coverage in the coverage map as reverted coverage. Reverted coverage is updated with successful
// coverage, the successful coverage is cleared.
// Returns a boolean indicating whether reverted coverage increased, and an error if one occurred.
func (cm *CmpDistanceMaps) RevertAll() {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Loop for each coverage map provided
	for _, mapsByAddressToMerge := range cm.maps {
		for _, cmpDistanceMap := range mapsByAddressToMerge {
			cmpDistanceMap.distanceMap.Reset()
		}
	}
}

// ContractCmpDistanceMap represents a data structure used to identify branch distance of a contract.
type ContractCmpDistanceMap struct {
	// distanceMap represents cmp distance for the contract bytecode, which did not encounter a revert and was
	// deemed successful.
	distanceMap *DistanceMapBranchData
}

// newContractCmpDistanceMap creates and returns a new ContractCmpDistanceMap.
func newContractCmpDistanceMap() *ContractCmpDistanceMap {
	return &ContractCmpDistanceMap{
		distanceMap: &DistanceMapBranchData{},
	}
}

// update creates updates the current ContractCmpDistanceMap with the provided one.
// Returns two booleans indicating whether successful or reverted coverage changed, or an error if one was encountered.
func (cm *ContractCmpDistanceMap) update(coverageMap *ContractCmpDistanceMap) (bool, error) {
	// Update our success coverage data
	changed, err := cm.distanceMap.update(coverageMap.distanceMap)
	if err != nil {
		return false, err
	}

	return changed, nil
}

// setDistanceAt sets the distance at a given branch within a ContractCmpDistanceMap used for
// "successful" coverage (non-reverted).
// Returns a boolean indicating whether new coverage was achieved, or an error if one occurred.
func (cm *ContractCmpDistanceMap) setDistanceAt(id uint64, distance *uint256.Int) (bool, error) {
	// Set our coverage data for the successful branch.
	return cm.distanceMap.setDistanceAt(id, distance)
}

// GetCoverageRate returns the covered branch size and the total branch size of the contract.
func (cm *ContractCmpDistanceMap) getCoveredCmpNum(includeReverted bool) int {
	if !includeReverted {
		return cm.distanceMap.getCoveredCmpNum()
	}
	allCoverage := &DistanceMapBranchData{}
	_, _ = allCoverage.update(cm.distanceMap)
	return allCoverage.getCoveredCmpNum()
}

// DistanceMapBranchData represents a data structure used to identify branch coverage of some init
// or runtime bytecode.
type DistanceMapBranchData struct {
	distance map[uint64]*uint256.Int
}

// Reset resets the branch coverage map data to be empty.
func (cm *DistanceMapBranchData) Reset() {
	cm.distance = make(map[uint64]*uint256.Int)
}

// update creates updates the current DistanceMapBranchData with the provided one.
// Returns a boolean indicating whether new coverage was achieved, or an error if one was encountered.
func (cm *DistanceMapBranchData) update(cmpDistanceMap *DistanceMapBranchData) (bool, error) {

	// If the current map has no execution data, simply set it to the provided one.
	if cm.distance == nil {
		cm.distance = make(map[uint64]*uint256.Int)
	}

	// Update each byte which represents a branch which was covered.
	changed := false
	for id := range cmpDistanceMap.distance {
		if _, exists := cm.distance[id]; !exists {
			cm.distance[id] = new(uint256.Int).Set(cmpDistanceMap.distance[id])
		} else if cm.distance[id].Gt(cmpDistanceMap.distance[id]) {
			cm.distance[id] = new(uint256.Int).Set(cmpDistanceMap.distance[id])
			changed = true
		}
	}

	return changed, nil
}

// setDistanceAt sets the distance at a given branch id within a DistanceMapBranchData.
// Returns a boolean indicating whether lower distance was achieved, or an error if one occurred.
func (cm *DistanceMapBranchData) setDistanceAt(id uint64, distance *uint256.Int) (bool, error) {

	if cm.distance == nil {
		cm.distance = make(map[uint64]*uint256.Int)
	}

	// If our program counter is in range, determine if we achieved new coverage for the first time, and update it.
	if _, exists := cm.distance[id]; !exists {
		cm.distance[id] = new(uint256.Int).Set(distance)
		return true, nil
	} else if cm.distance[id].Gt(distance) {
		cm.distance[id] = new(uint256.Int).Set(distance)
		return true, nil
	}

	// Since it is possible that the program counter is larger than the code size (e.g., malformed bytecode), we will
	// simply return false with no error
	return false, nil
}

func (cm *DistanceMapBranchData) getCoveredCmpNum() int {
	return len(cm.distance)
}

package branchdistance

import (
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/crypto"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/holiman/uint256"
)

// BranchDistanceMaps represents a data structure used to identify branch distance of various smart contracts
// across a transaction or multiple transactions.
type BranchDistanceMaps struct {
	// maps represents a structure used to track every ContractCoverageMap by a given deployed address/lookup hash.
	maps map[common.Hash]map[common.Address]*ContractBranchDistanceMap

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
	cachedMap *ContractBranchDistanceMap

	// updateLock is a lock to offer concurrent thread safety for map accesses.
	updateLock sync.Mutex
}

type DumpDistance map[string]map[string]uint

func (cm *BranchDistanceMaps) DumpBranchDistance(includeReverted bool) DumpDistance {
	c := make(DumpDistance)
	for i := range cm.maps {
		c[i.String()] = make(map[string]uint)
		for j := range cm.maps[i] {
			coveredBranchSize, totalBranchSize := cm.maps[i][j].GetCoverageRate(includeReverted)
			c[i.String()][j.String()] = uint(float64(coveredBranchSize) / float64(totalBranchSize))
		}
	}
	return c
}

func (cm *BranchDistanceMaps) TotalBranchDistance(includeReverted bool, targetAddresses []common.Address) (int, int) {
	coveredBranchSize := 0
	totalBranchSize := 0
	for i := range cm.maps {
		if len(targetAddresses) > 0 {
			for _, j := range targetAddresses {
				ccm, exists := cm.maps[i][j]
				if !exists {
					continue
				}
				c, t := ccm.GetCoverageRate(includeReverted)
				coveredBranchSize += c
				totalBranchSize += t
			}
		} else {
			for j := range cm.maps[i] {
				c, t := cm.maps[i][j].GetCoverageRate(includeReverted)
				coveredBranchSize += c
				totalBranchSize += t
			}
		}
	}
	return coveredBranchSize, totalBranchSize
}

// NewBranchDistanceMaps initializes a new BranchDistanceMaps object.
func NewBranchDistanceMaps() *BranchDistanceMaps {
	maps := &BranchDistanceMaps{}
	maps.Reset()
	return maps
}

// Reset clears the coverage state for the BranchDistanceMaps.
func (cm *BranchDistanceMaps) Reset() {
	cm.maps = make(map[common.Hash]map[common.Address]*ContractBranchDistanceMap)
	cm.cachedCodeAddress = common.Address{}
	cm.cachedCodeHash = common.Hash{}
	cm.cachedMap = nil
}

// getContractBranchDistanceMapHash obtain the hash used to look up a given contract's ContractBranchDistanceMap.
// If this is init bytecode, metadata and abi arguments will attempt to be stripped, then a hash is computed.
// If this is runtime bytecode, the metadata ipfs/swarm hash will be used if available, otherwise the bytecode
// is hashed.
// Returns the resulting lookup hash.
func getContractBranchDistanceMapHash(bytecode []byte, init bool) common.Hash {
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
func (cm *BranchDistanceMaps) GetContractDistanceDistanceMap(bytecode []byte, init bool) (*ContractBranchDistanceMap, error) {
	// Obtain the lookup hash
	hash := getContractBranchDistanceMapHash(bytecode, init)

	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Loop through all coverage maps for this hash and collect our total coverage.
	if distanceByAddresses, ok := cm.maps[hash]; ok {
		totalDistance := newContractBranchDistanceMap()
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
func (cm *BranchDistanceMaps) Update(coverageMaps *BranchDistanceMaps) (bool, error) {
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
				mapsByAddress = make(map[common.Address]*ContractBranchDistanceMap)
				cm.maps[codeHash] = mapsByAddress
			}

			// If a coverage map for this address already exists in our current mapping, update it with the one
			// to merge. If it doesn't exist, set it to the one to merge.
			if existingCoverageMap, codeAddressExists := mapsByAddress[codeAddress]; codeAddressExists {
				sChanged, err := existingCoverageMap.update(coverageMapToMerge)
				distanceChanged = distanceChanged || sChanged
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
func (cm *BranchDistanceMaps) SetAt(codeAddress common.Address, codeLookupHash common.Hash, branchSize, id int, distance *uint256.Int) (bool, error) {
	// If the branch size is zero, do nothing
	if branchSize == 0 {
		return false, nil
	}

	// Define variables used to update coverage maps and track changes.
	var (
		addedNewMap       bool
		changedInMap      bool
		branchDistanceMap *ContractBranchDistanceMap
		err               error
	)

	// Try to obtain a coverage map from our cache
	if cm.cachedMap != nil && cm.cachedCodeAddress == codeAddress && cm.cachedCodeHash == codeLookupHash {
		branchDistanceMap = cm.cachedMap
	} else {
		// If a coverage map lookup for this code hash doesn't exist, create the mapping.
		mapsByCodeAddress, codeHashExists := cm.maps[codeLookupHash]
		if !codeHashExists {
			mapsByCodeAddress = make(map[common.Address]*ContractBranchDistanceMap)
			cm.maps[codeLookupHash] = mapsByCodeAddress
		}

		// Obtain the coverage map for this code address if it already exists. If it does not, create a new one.
		if existingCoverageMap, codeAddressExists := mapsByCodeAddress[codeAddress]; codeAddressExists {
			branchDistanceMap = existingCoverageMap
		} else {
			branchDistanceMap = newContractBranchDistanceMap()
			cm.maps[codeLookupHash][codeAddress] = branchDistanceMap
			addedNewMap = true
		}

		// Set our cached variables for faster coverage setting next time this method is called.
		cm.cachedMap = branchDistanceMap
		cm.cachedCodeHash = codeLookupHash
		cm.cachedCodeAddress = codeAddress
	}

	// Set our distance in the map and return our change state
	changedInMap, err = branchDistanceMap.setDistanceAt(branchSize, id, distance)
	return addedNewMap || changedInMap, err
}

// RevertAll sets all coverage in the coverage map as reverted coverage. Reverted coverage is updated with successful
// coverage, the successful coverage is cleared.
// Returns a boolean indicating whether reverted coverage increased, and an error if one occurred.
func (cm *BranchDistanceMaps) RevertAll() {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Loop for each coverage map provided
	for _, mapsByAddressToMerge := range cm.maps {
		for _, contractDistanceMap := range mapsByAddressToMerge {
			// Clear our successful coverage, as these maps were marked as reverted.
			contractDistanceMap.distanceMap.Reset()
		}
	}
}

// ContractBranchDistanceMap represents a data structure used to identify branch distance of a contract.
type ContractBranchDistanceMap struct {
	// successfulCoverage represents branch distance for the contract bytecode, which did not encounter a revert and was
	// deemed successful.
	distanceMap *DistanceMapBranchData
}

// newContractBranchDistanceMap creates and returns a new ContractBranchDistanceMap.
func newContractBranchDistanceMap() *ContractBranchDistanceMap {
	return &ContractBranchDistanceMap{
		distanceMap: &DistanceMapBranchData{},
	}
}

// update creates updates the current ContractBranchDistanceMap with the provided one.
// Returns two booleans indicating whether successful or reverted coverage changed, or an error if one was encountered.
func (cm *ContractBranchDistanceMap) update(coverageMap *ContractBranchDistanceMap) (bool, error) {
	// Update our success coverage data
	successfulCoverageChanged, err := cm.distanceMap.update(coverageMap.distanceMap)
	if err != nil {
		return false, err
	}

	return successfulCoverageChanged, nil
}

// setDistanceAt sets the distance at a given branch within a ContractBranchDistanceMap used for
// "successful" coverage (non-reverted).
// Returns a boolean indicating whether new coverage was achieved, or an error if one occurred.
func (cm *ContractBranchDistanceMap) setDistanceAt(branchSize, id int, distance *uint256.Int) (bool, error) {
	// Set our coverage data for the successful branch.
	return cm.distanceMap.setDistanceAt(branchSize, id, distance)
}

// GetCoverageRate returns the covered branch size and the total branch size of the contract.
func (cm *ContractBranchDistanceMap) GetCoverageRate(includeReverted bool) (int, int) {
	if !includeReverted {
		return cm.distanceMap.getDistance()
	}
	allCoverage := &DistanceMapBranchData{}
	_, _ = allCoverage.update(cm.distanceMap)
	return allCoverage.getDistance()
}

// DistanceMapBranchData represents a data structure used to identify branch coverage of some init
// or runtime bytecode.
type DistanceMapBranchData struct {
	executedFlags []byte
	distance      map[int]*uint256.Int
}

// Reset resets the branch coverage map data to be empty.
func (cm *DistanceMapBranchData) Reset() {
	cm.executedFlags = nil
	cm.distance = make(map[int]*uint256.Int)
}

// update creates updates the current DistanceMapBranchData with the provided one.
// Returns a boolean indicating whether new coverage was achieved, or an error if one was encountered.
func (cm *DistanceMapBranchData) update(branchDistanceMap *DistanceMapBranchData) (bool, error) {
	// If the coverage map execution data provided is nil, exit early
	if branchDistanceMap.executedFlags == nil {
		return false, nil
	}

	// If the current map has no execution data, simply set it to the provided one.
	if cm.executedFlags == nil {
		cm.executedFlags = branchDistanceMap.executedFlags
		cm.distance = make(map[int]*uint256.Int)
		// fmt.Println(branchDistanceMap.executedFlags, branchDistanceMap.distance)
		for i := 0; i < len(branchDistanceMap.executedFlags); i++ {
			if branchDistanceMap.executedFlags[i] == 1 {
				cm.distance[i] = new(uint256.Int).Set(branchDistanceMap.distance[i])
			}
		}
		// fmt.Println("new distance map", cm.distance)
		return true, nil
	}

	// Update each byte which represents a branch which was covered.
	changed := false
	for i := 0; i < len(cm.executedFlags) && i < len(branchDistanceMap.executedFlags); i++ {
		if cm.executedFlags[i] == 0 && branchDistanceMap.executedFlags[i] != 0 {
			cm.executedFlags[i] = 1
			cm.distance[i] = new(uint256.Int).Set(branchDistanceMap.distance[i])
			// fmt.Println("new distance", cm.distance)
			changed = true
		} else if cm.executedFlags[i] == 1 && branchDistanceMap.executedFlags[i] == 1 {
			if cm.distance[i].Gt(branchDistanceMap.distance[i]) {
				cm.distance[i] = new(uint256.Int).Set(branchDistanceMap.distance[i])
				// fmt.Println("closer distance", cm.distance)
				changed = true
			}
		}
	}
	return changed, nil
}

// setDistanceAt sets the distance at a given branch id within a DistanceMapBranchData.
// Returns a boolean indicating whether lower distance was achieved, or an error if one occurred.
func (cm *DistanceMapBranchData) setDistanceAt(branchSize, id int, distance *uint256.Int) (bool, error) {
	// If the execution flags don't exist, create them for this code size.
	if cm.executedFlags == nil {
		cm.executedFlags = make([]byte, branchSize)
	}

	if cm.distance == nil {
		cm.distance = make(map[int]*uint256.Int)
	}

	// If our program counter is in range, determine if we achieved new coverage for the first time, and update it.
	if id < len(cm.executedFlags) {
		if cm.executedFlags[id] == 0 {
			cm.executedFlags[id] = 1
			cm.distance[id] = distance
			return true, nil
		} else {
			if cm.distance[id].Gt(distance) {
				cm.distance[id] = distance
				return true, nil
			}
		}
	}

	// Since it is possible that the program counter is larger than the code size (e.g., malformed bytecode), we will
	// simply return false with no error
	return false, nil
}

func (cm *DistanceMapBranchData) getDistance() (int, int) {
	coveredBranchSize := 0
	for _, v := range cm.executedFlags {
		if v != 0 {
			coveredBranchSize++
		}
	}
	return coveredBranchSize, len(cm.executedFlags)
}

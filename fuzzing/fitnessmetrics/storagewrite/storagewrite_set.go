package storagewrite

import (
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/holiman/uint256"
)

type StorageWriteSet struct {
	successSet map[string]*StorageWrite
	lock       sync.RWMutex
}

func (ds *StorageWriteSet) TotalStorageWriteCount() int {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	count := len(ds.successSet)
	return count
}

// NewStorageWriteSet initializes a new StorageWriteSet object.
func NewStorageWriteSet() *StorageWriteSet {
	maps := &StorageWriteSet{}
	maps.Reset()
	return maps
}

// Reset clears the storage-write state for the StorageWriteSet.
func (ds *StorageWriteSet) Reset() {
	ds.successSet = make(map[string]*StorageWrite)
}

// Update updates the current storage-write set with the provided ones.
// Returns two booleans indicating whether successful or reverted storage-write increased, or an error if one occurred.
func (ds *StorageWriteSet) Update(storageWriteSet *StorageWriteSet) (bool, error) {
	// If our maps provided are nil, do nothing
	if storageWriteSet == nil {
		return false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	successUpdated := false

	for key, storageWrite := range storageWriteSet.successSet {
		if _, exists := ds.successSet[key]; !exists {
			ds.successSet[key] = storageWrite
			successUpdated = true
		}
	}

	return successUpdated, nil
}

func (ds *StorageWriteSet) SetWrite(storageAddress common.Address, slot, value *uint256.Int, codeAddress common.Address, create bool, pc uint64) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	variable := &StorageSlot{
		Address: storageAddress,
		Slot:    slot,
		Value:   value,
	}
	position := &ProgramPosition{
		Address: codeAddress,
		Create:  create,
		Pc:      pc,
	}

	storageWrite := &StorageWrite{
		Position: position,
		Variable: variable,
	}

	storageWritebucket := storageWrite.Bucket()
	// storageWriteStr := storageWrite.String()
	if _, exists := ds.successSet[storageWritebucket]; !exists {
		ds.successSet[storageWritebucket] = storageWrite
		return true, nil
	}

	return false, nil
}

// RevertAll sets all storage-write in the set as reverted storage-write. Reverted storage-write set is
// updated with successful storage-write set, the successful storage-write set is cleared.
// Returns a boolean indicating whether reverted storage-write set increased, and an error if one occurred.
func (ds *StorageWriteSet) RevertAll() {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.Reset()
}

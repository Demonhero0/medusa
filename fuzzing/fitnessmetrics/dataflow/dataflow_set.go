package dataflow

import (
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/holiman/uint256"
)

type DataflowSet struct {
	set       map[string]*Dataflow
	writeMaps map[string]map[string]*ProgramPosition
	lock      sync.RWMutex
}

func (ds *DataflowSet) TotalDataflowCount() int {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	count := len(ds.set)
	return count
}

// NewDataflowSet initializes a new DataflowSet object.
func NewDataflowSet() *DataflowSet {
	maps := &DataflowSet{}
	maps.Reset()
	return maps
}

// Reset clears the dataflow state for the DataflowSet.
func (ds *DataflowSet) Reset() {
	ds.set = make(map[string]*Dataflow)
	ds.writeMaps = make(map[string]map[string]*ProgramPosition)
}

// Update updates the current dataflow set with the provided ones.
// Returns two booleans indicating whether dataflow increased, or an error if one occurred.
func (ds *DataflowSet) Update(dataflowSet *DataflowSet) (bool, error) {
	// If our maps provided are nil, do nothing
	if dataflowSet == nil {
		return false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	updated := false

	for key, dataflow := range dataflowSet.set {
		if _, exists := ds.set[key]; !exists {
			ds.set[key] = dataflow
			updated = true
		}
	}

	return updated, nil
}

func (ds *DataflowSet) SetWrite(storageAddress common.Address, slot *uint256.Int, codeAddress common.Address, create bool, pc uint64) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	variable := &StorageSlot{
		Address: storageAddress,
		Slot:    slot,
	}
	writeMaps := ds.writeMaps[variable.String()]
	if writeMaps == nil {
		writeMaps = make(map[string]*ProgramPosition)
		ds.writeMaps[variable.String()] = writeMaps
	}

	write := &ProgramPosition{
		Address: codeAddress,
		Create:  create,
		Pc:      pc,
	}
	writeStr := write.String()
	if _, exists := writeMaps[writeStr]; !exists {
		writeMaps[writeStr] = write
		return true, nil
	}

	return false, nil
}

func (ds *DataflowSet) SetRead(storageAddress common.Address, slot *uint256.Int, codeAddress common.Address, create bool, pc uint64) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	variable := &StorageSlot{
		Address: storageAddress,
		Slot:    slot,
	}
	writeMaps := ds.writeMaps[variable.String()]
	if writeMaps == nil {
		return false, nil
	}

	updated := false

	read := &ProgramPosition{
		Address: codeAddress,
		Create:  create,
		Pc:      pc,
	}
	for _, write := range writeMaps {
		dataflow := &Dataflow{
			Write:    write,
			Read:     read,
			Variable: variable,
		}
		dataflowStr := dataflow.String()
		if _, exists := ds.set[dataflowStr]; !exists {
			ds.set[dataflowStr] = dataflow
			updated = true
		}
	}

	return updated, nil
}

func (ds *DataflowSet) RevertAll() {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.Reset()
}

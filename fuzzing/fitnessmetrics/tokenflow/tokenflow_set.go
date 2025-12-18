package tokenflow

import (
	"sync"

	"github.com/crytic/medusa-geth/common"
	"github.com/holiman/uint256"
)

type TokenflowSet struct {
	successSet  map[string]*Tokenflow
	revertedSet map[string]*Tokenflow
	lock        sync.RWMutex
}

func (ds *TokenflowSet) TotalTokenflowCount(includeReverted bool) int {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	count := len(ds.successSet)
	if includeReverted {
		for key, _ := range ds.revertedSet {
			if _, exists := ds.successSet[key]; !exists {
				count++
			}
		}
	}
	return count
}

// NewTokenflowSet initializes a new TokenflowSet object.
func NewTokenflowSet() *TokenflowSet {
	maps := &TokenflowSet{}
	maps.Reset()
	return maps
}

// Reset clears the dataflow state for the TokenflowSet.
func (ds *TokenflowSet) Reset() {
	ds.successSet = make(map[string]*Tokenflow)
	ds.revertedSet = make(map[string]*Tokenflow)
}

// Update updates the current storage-write set with the provided ones.
// Returns two booleans indicating whether successful or reverted storage-write increased, or an error if one occurred.
func (ds *TokenflowSet) Update(storageWriteSet *TokenflowSet) (bool, error) {
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

func (ds *TokenflowSet) SetTokenFlow(storageAddress common.Address, codeAddress common.Address, create bool, pc uint64, amount *uint256.Int, from, to, token common.Address) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	// fmt.Println(pc, token)

	flow := &Flow{
		From:   from,
		To:     to,
		Amount: uint256.NewInt(0).Set(amount),
		Token:  token,
	}

	position := &ProgramPosition{
		Address: codeAddress,
		Create:  create,
		Pc:      pc,
	}

	tokenflow := &Tokenflow{
		Position: position,
		Flow:     flow,
	}

	tokenflowStr := tokenflow.String()
	if _, exists := ds.successSet[tokenflowStr]; !exists {
		ds.successSet[tokenflowStr] = tokenflow
		return true, nil
	}

	return false, nil
}

// RevertAll sets all storage-write in the set as reverted storage-write. Reverted storage-write set is
// updated with successful storage-write set, the successful storage-write set is cleared.
// Returns a boolean indicating whether reverted storage-write set increased, and an error if one occurred.
func (ds *TokenflowSet) RevertAll() {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.successSet = make(map[string]*Tokenflow)
}

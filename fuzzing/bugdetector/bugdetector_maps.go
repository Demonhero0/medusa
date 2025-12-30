package bugdetector

import (
	"sync"
)

var _bugTypes = []string{
	"reentrancy",
}

type BugMap struct {
	bugMap map[string]bool
	lock   sync.RWMutex
}

func (ds *BugMap) BugDetectionResult() []string {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	var bugs []string
	for bug := range ds.bugMap {
		bugs = append(bugs, bug)
	}

	return bugs
}

// NewBugMap initializes a new BugMap object.
func NewBugMap() *BugMap {
	maps := &BugMap{}
	maps.Reset()
	return maps
}

// Reset clears the storage-write state for the BugMap.
func (ds *BugMap) Reset() {
	ds.bugMap = make(map[string]bool)
}

// Update updates the current storage-write set with the provided ones.
// Returns two booleans indicating whether successful or reverted storage-write increased, or an error if one occurred.
func (ds *BugMap) Update(bugMMap *BugMap) (bool, error) {
	// If our maps provided are nil, do nothing
	if bugMMap == nil {
		return false, nil
	}

	// Acquire our thread lock and defer our unlocking for when we exit this method
	ds.lock.Lock()
	defer ds.lock.Unlock()

	successUpdated := false
	for bug := range bugMMap.bugMap {
		ds.bugMap[bug] = true
		successUpdated = true
	}

	return successUpdated, nil
}

func (ds *BugMap) CoverBug(bugId string) (bool, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	_, exists := ds.bugMap[bugId]
	if exists {
		return false, nil
	}
	ds.bugMap[bugId] = true

	return true, nil
}

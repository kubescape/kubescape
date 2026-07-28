package v1

import (
	"context"
	"fmt"
	"sync"
)

type serverState struct {
	statusID map[string]context.CancelFunc
	latestID string
	mtx      sync.RWMutex
}

// isBusy is server busy with ID, if id is empty will check for latest ID
func (s *serverState) isBusy(id string) bool {
	s.mtx.RLock()
	if id == "" {
		id = s.latestID
	}
	_, busy := s.statusID[id]
	s.mtx.RUnlock()
	return busy
}

func (s *serverState) setBusy(id string, cancel context.CancelFunc) {
	s.mtx.Lock()
	s.statusID[id] = cancel
	s.latestID = id
	s.mtx.Unlock()
}

func (s *serverState) setNotBusy(id string) {
	s.mtx.Lock()
	delete(s.statusID, id)
	s.mtx.Unlock()
}

func (s *serverState) getLatestID() string {
	s.mtx.RLock()
	id := s.latestID
	s.mtx.RUnlock()
	return id
}

func (s *serverState) len() int {
	s.mtx.RLock()
	l := len(s.statusID)
	s.mtx.RUnlock()
	return l
}

func (s *serverState) removeAllIfIdle(removeFn func()) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if len(s.statusID) > 0 {
		return fmt.Errorf("cannot delete all results while a scan is in progress")
	}
	removeFn()
	return nil
}

// cancel invokes the CancelFunc stored for id and removes it from the busy
// set. It returns false if id has no in-flight scan, either because it is
// unknown or the scan has already finished.
func (s *serverState) cancel(id string) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	cancelFunc, ok := s.statusID[id]
	if !ok {
		return false
	}
	cancelFunc()
	delete(s.statusID, id)
	return true
}

// cancelAll invokes every stored CancelFunc and clears the busy set.
func (s *serverState) cancelAll() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for id, cancelFunc := range s.statusID {
		cancelFunc()
		delete(s.statusID, id)
	}
}

func newServerState() *serverState {
	return &serverState{
		statusID: make(map[string]context.CancelFunc),
		mtx:      sync.RWMutex{},
	}
}

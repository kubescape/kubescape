package v1

import "sync"

type serverState struct {
	statusID map[string]bool
	latestID string
	mtx      sync.RWMutex
}

// isBusy is server busy with ID, if id is empty will check for latest ID
func (s *serverState) isBusy(id string) bool {
	s.mtx.RLock()
	if id == "" {
		id = s.latestID
	}
	busy := s.statusID[id]
	s.mtx.RUnlock()
	return busy
}

func (s *serverState) setBusy(id string) {
	s.mtx.Lock()
	s.statusID[id] = true
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

func newServerState() *serverState {
	return &serverState{
		statusID: make(map[string]bool),
		mtx:      sync.RWMutex{},
	}
}

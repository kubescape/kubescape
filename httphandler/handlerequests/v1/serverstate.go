package v1

import "sync"

type serverState struct {
	// response string
	busy     bool
	id       string
	latestID string
	mtx      sync.RWMutex
}

func (s *serverState) isBusy() bool {
	s.mtx.RLock()
	busy := s.busy
	s.mtx.RUnlock()
	return busy
}

func (s *serverState) setBusy() {
	s.mtx.Lock()
	s.busy = true
	s.mtx.Unlock()
}

func (s *serverState) setNotBusy() {
	s.mtx.Lock()
	s.busy = false
	s.latestID = s.id
	s.id = ""
	s.mtx.Unlock()
}

func (s *serverState) getID() string {
	s.mtx.RLock()
	id := s.id
	s.mtx.RUnlock()
	return id
}

func (s *serverState) setID(id string) {
	s.mtx.Lock()
	s.id = id
	s.mtx.Unlock()
}

func (s *serverState) getLatestID() string {
	s.mtx.RLock()
	id := s.latestID
	s.mtx.RUnlock()
	return id
}

func newServerState() *serverState {
	return &serverState{
		busy: false,
		mtx:  sync.RWMutex{},
	}
}

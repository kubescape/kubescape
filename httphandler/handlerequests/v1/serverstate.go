package v1

import (
	"context"
	"fmt"
	"sync"
)

type scanEntry struct {
	cancel    context.CancelFunc
	cancelled bool
}

type serverState struct {
	statusID         map[string]*scanEntry
	latestID         string
	latestUserScanID string
	mtx              sync.RWMutex
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
	s.statusID[id] = &scanEntry{cancel: cancel}
	s.latestID = id
	s.mtx.Unlock()
}

func (s *serverState) setNotBusy(id string) {
	s.mtx.Lock()
	delete(s.statusID, id)
	if s.latestUserScanID == id {
		s.latestUserScanID = ""
	}
	s.mtx.Unlock()
}

func (s *serverState) getLatestID() string {
	s.mtx.RLock()
	id := s.latestID
	s.mtx.RUnlock()
	return id
}

// setLatestUserScanID records id as the scan currently executing on behalf of
// the Scan handler (not Metrics). watchForScan calls this when it dequeues a
// user-submitted request, so it always reflects the scan actually running,
// not merely the last one accepted into the queue.
func (s *serverState) setLatestUserScanID(id string) {
	s.mtx.Lock()
	s.latestUserScanID = id
	s.mtx.Unlock()
}

func (s *serverState) getLatestUserScanID() string {
	s.mtx.RLock()
	id := s.latestUserScanID
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

// releaseLocked invokes the CancelFunc for id and marks it cancelled, if
// present. Must be called with mtx held. It never removes the entry --
// setNotBusy owns removal, so isBusy/isCancelled stay accurate until the
// scan has actually stopped running.
func (s *serverState) releaseLocked(id string) bool {
	entry, ok := s.statusID[id]
	if !ok {
		return false
	}
	entry.cancelled = true
	entry.cancel()
	return true
}

// cancel invokes the CancelFunc stored for id and marks it cancelled. It
// returns false if id has no in-flight scan, either because it is unknown or
// the scan has already finished.
func (s *serverState) cancel(id string) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.releaseLocked(id)
}

// releaseCancel invokes the CancelFunc for id, if present, without regard to
// whether it was already cancelled. executeScan calls this on every
// completion path (success, failure, or cancellation) so a scan's cancel
// func is always released once it stops running.
func (s *serverState) releaseCancel(id string) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.releaseLocked(id)
}

// isCancelled reports whether id was cancelled while still queued or while
// running. It stays true after cancel() until setNotBusy removes the entry.
func (s *serverState) isCancelled(id string) bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	entry, ok := s.statusID[id]
	if !ok {
		return false
	}
	return entry.cancelled
}

func newServerState() *serverState {
	return &serverState{
		statusID: make(map[string]*scanEntry),
		mtx:      sync.RWMutex{},
	}
}

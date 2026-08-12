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
	statusID          map[string]*scanEntry
	latestID          string
	latestUserScanID  string
	runningUserScanID string
	mtx               sync.RWMutex
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

// admitUserScan runs the whole admission step for a user scan under a single
// hold of the state mutex: it marks id busy, attempts the enqueue, and -- only
// if that succeeded -- records id as the latest accepted user scan. It returns
// false when enqueue failed, having rolled the busy entry back.
//
// enqueue must not block; Scan passes the non-blocking channel send. Holding
// the mutex across it is what keeps acceptance order and latestUserScanID order
// identical. With the enqueue and the bookkeeping in separate critical
// sections, two concurrent Scan handlers can enqueue as A-then-B but run their
// bookkeeping as B-then-A, leaving latestUserScanID on the older scan -- so
// Status and the offline Results fallback resolve "latest" to a stale scan.
//
// The rollback deliberately leaves latestID pointing at the rejected scan,
// matching what setBusy followed by setNotBusy did before. runningUserScanID
// needs no rollback: only watchForScan sets it, and it never saw this id.
func (s *serverState) admitUserScan(id string, cancel context.CancelFunc, enqueue func() bool) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.statusID[id] = &scanEntry{cancel: cancel}
	s.latestID = id

	if !enqueue() {
		delete(s.statusID, id)
		return false
	}

	s.latestUserScanID = id
	return true
}

func (s *serverState) setNotBusy(id string) {
	s.mtx.Lock()
	delete(s.statusID, id)
	if s.runningUserScanID == id {
		s.runningUserScanID = ""
	}
	s.mtx.Unlock()
}

func (s *serverState) getLatestID() string {
	s.mtx.RLock()
	id := s.latestID
	s.mtx.RUnlock()
	return id
}

// setLatestUserScanID records id as the most recent scan accepted from the Scan
// handler. latestUserScanID is the user-scan counterpart of latestID: it is
// deliberately never cleared, so Status and the offline Results fallback can
// still resolve "latest" after the scan finishes, and Metrics never writes it,
// which is what keeps a /v1/metrics scrape from hijacking those two endpoints.
//
// Request handling must not call this directly -- admitUserScan writes the
// field as part of the admission critical section, and updating it separately
// is exactly the race that serialization exists to prevent. It remains for
// tests that need to seed an already-accepted user scan.
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

// setRunningUserScanID records id as the scan currently executing on behalf of
// the Scan handler (not Metrics). watchForScan calls this when it dequeues a
// user-submitted request, so it always reflects the scan actually running, not
// merely the last one accepted into the queue -- which is what CancelScan needs
// to target. setNotBusy clears it when that scan stops running.
func (s *serverState) setRunningUserScanID(id string) {
	s.mtx.Lock()
	s.runningUserScanID = id
	s.mtx.Unlock()
}

func (s *serverState) getRunningUserScanID() string {
	s.mtx.RLock()
	id := s.runningUserScanID
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

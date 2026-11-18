package lsp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// document is what the server knows of an open text document. The server never
// holds its text: v1 scans saved files on disk.
type document struct {
	uri     string // as the client sent it, used when publishing
	path    string
	version int32
	dirty   bool // changed in the editor since it was last saved
	openID  uint64
}

// documentStore tracks the open documents. It is safe for concurrent use.
type documentStore struct {
	mu     sync.Mutex
	nextID uint64
	docs   map[string]document // by pathKey
}

func newDocumentStore() *documentStore {
	return &documentStore{docs: make(map[string]document)}
}

// pathKey is how paths are compared: Windows and macOS file systems are, by
// default, case insensitive.
func pathKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(path)
	}
	return path
}

func (s *documentStore) open(uri, path string, version int32, dirty bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.docs[pathKey(path)] = document{uri: uri, path: path, version: version, dirty: dirty, openID: s.nextID}
}

// change records a new version and marks the document dirty. It reports whether
// the document is open.
func (s *documentStore) change(path string, version int32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.docs[pathKey(path)]
	if !ok {
		return false
	}
	d.version, d.dirty = version, true
	s.docs[pathKey(path)] = d
	return true
}

// saved marks the document as matching the disk and returns it.
func (s *documentStore) saved(path string) (document, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.docs[pathKey(path)]
	if !ok {
		return document{}, false
	}
	d.dirty = false
	s.docs[pathKey(path)] = d
	return d, true
}

// close forgets the document and returns it.
func (s *documentStore) close(path string) (document, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.docs[pathKey(path)]
	delete(s.docs, pathKey(path))
	return d, ok
}

func (s *documentStore) get(path string) (document, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.docs[pathKey(path)]
	return d, ok
}

// snapshot returns the open documents.
func (s *documentStore) snapshot() []document {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]document, 0, len(s.docs))
	for _, d := range s.docs {
		out = append(out, d)
	}
	return out
}

// existing returns the paths that name something on disk.
func existing(paths []string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

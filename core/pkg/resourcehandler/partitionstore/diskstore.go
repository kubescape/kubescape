package partitionstore

import (
	"bufio"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"k8s.io/apimachinery/pkg/util/json"
)

const maxScannerCapacity = 10 * 1024 * 1024 // 10 MB per JSON object line

// DiskStore implements Store by spilling namespaced Kubernetes resources to private,
// owner-only temporary files on disk. It bounds live memory to active write buffers
// and manages a bounded LRU pool of open file descriptors.
type DiskStore struct {
	mu                   sync.Mutex
	opts                 Options
	rootDir              string
	stagingDir           string
	partitionsDir        string
	activeGVR            string
	stagingFile          *os.File
	stagingWriter        *bufio.Writer
	stagingPath          string
	stagingCounts        map[string]int
	committedCounts      map[string]int
	namespaces           map[string]struct{}
	totalResources       int
	filePool             *fdPool
	sealed               bool
	closed               bool
	unrestoredPartitions map[string]int64
	rollbackErr          error
}

// NewDiskStore initializes and returns a new disk-backed partition store.
// Temporary directory is created with mode 0700.
func NewDiskStore(opts ...Option) (*DiskStore, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	tempDir, err := os.MkdirTemp(options.BaseDir, "kubescape-spill-*")
	if err != nil {
		if isDiskFull(err) {
			return nil, fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return nil, fmt.Errorf("failed to create spill directory: %w", err)
	}

	// Enforce 0700 permissions strictly
	if err := os.Chmod(tempDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to enforce owner-only permissions on %s: %w", tempDir, err)
	}

	stagingDir := filepath.Join(tempDir, "staging")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		if isDiskFull(err) {
			return nil, fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}

	partitionsDir := filepath.Join(tempDir, "partitions")
	if err := os.Mkdir(partitionsDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		if isDiskFull(err) {
			return nil, fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return nil, fmt.Errorf("failed to create partitions directory: %w", err)
	}

	ds := &DiskStore{
		opts:                 options,
		rootDir:              tempDir,
		stagingDir:           stagingDir,
		partitionsDir:        partitionsDir,
		stagingCounts:        make(map[string]int),
		committedCounts:      make(map[string]int),
		namespaces:           make(map[string]struct{}),
		unrestoredPartitions: make(map[string]int64),
	}
	ds.filePool = newFDPool(partitionsDir, options.MaxOpenFiles, options.FileBufferSize)
	return ds, nil
}

// RootDir returns the absolute path of the root temporary spill directory.
func (d *DiskStore) RootDir() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rootDir
}

func (d *DiskStore) BeginGVR(ctx context.Context, gvr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}
	if len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return fmt.Errorf("%w: cannot begin transaction on corrupted store: %v", ErrStoreCorrupted, d.rollbackErr)
	}
	if d.sealed {
		return ErrStoreSealed
	}
	if d.activeGVR != "" {
		return ErrGVRAlreadyActive
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	stagingFilename := fmt.Sprintf("%x.jsonl", sha256.Sum256([]byte(gvr)))
	stagingPath := filepath.Join(d.stagingDir, stagingFilename)
	file, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if isDiskFull(err) {
			return fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return fmt.Errorf("failed to open staging file for GVR %s: %w", gvr, err)
	}

	d.activeGVR = gvr
	d.stagingPath = stagingPath
	d.stagingFile = file
	d.stagingWriter = bufio.NewWriterSize(file, d.opts.FileBufferSize)
	d.stagingCounts = make(map[string]int)
	return nil
}

func (d *DiskStore) Put(ctx context.Context, namespace string, obj workloadinterface.IMetadata) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}
	if len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return fmt.Errorf("%w: cannot write to corrupted store: %v", ErrStoreCorrupted, d.rollbackErr)
	}
	if d.sealed {
		return ErrStoreSealed
	}
	if d.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	rec := newRecord(d.activeGVR, namespace, obj)
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to serialize resource %s in namespace %s: %w", rec.ID, namespace, err)
	}

	if _, err := d.stagingWriter.Write(data); err != nil {
		if isDiskFull(err) {
			return fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return fmt.Errorf("failed to write resource %s in namespace %s: %w", rec.ID, namespace, err)
	}
	if err := d.stagingWriter.WriteByte('\n'); err != nil {
		if isDiskFull(err) {
			return fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return fmt.Errorf("failed to write record delimiter for resource %s: %w", rec.ID, err)
	}

	d.stagingCounts[namespace]++
	return nil
}

func (d *DiskStore) CommitGVR(ctx context.Context, gvr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}
	if d.sealed {
		return ErrStoreSealed
	}
	if d.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if d.activeGVR != gvr {
		return ErrMismatchedGVR
	}

	// If there are unrestored partitions from a previous failed commit, attempt recovery now
	if len(d.unrestoredPartitions) > 0 {
		var recoverErrs []error
		for ns, origOffset := range d.unrestoredPartitions {
			if err := d.filePool.truncateAndReset(ns, origOffset); err != nil {
				recoverErrs = append(recoverErrs, fmt.Errorf("failed to recover partition %s: %w", ns, err))
			} else {
				delete(d.unrestoredPartitions, ns)
			}
		}
		if len(d.unrestoredPartitions) > 0 {
			d.rollbackErr = errors.Join(recoverErrs...)
			return fmt.Errorf("%w: cannot commit with unrestored rollback failures: %v", ErrStoreCorrupted, d.rollbackErr)
		}
		d.rollbackErr = nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Flush and close the staging writer
	if d.stagingWriter != nil {
		if err := d.stagingWriter.Flush(); err != nil {
			if isDiskFull(err) {
				return fmt.Errorf("%w: %v", ErrDiskFull, err)
			}
			return fmt.Errorf("failed to flush staging writer for GVR %s: %w", gvr, err)
		}
	}
	if d.stagingFile != nil {
		if err := d.stagingFile.Close(); err != nil {
			return fmt.Errorf("failed to close staging file for GVR %s: %w", gvr, err)
		}
		d.stagingFile = nil
		d.stagingWriter = nil
	}

	// If no items were staged for this GVR, just clean up staging file
	if len(d.stagingCounts) == 0 {
		_ = os.Remove(d.stagingPath)
		d.resetStaging()
		return nil
	}

	// Reopen staging file for reading
	stagingReadFile, err := os.Open(d.stagingPath)
	if err != nil {
		return fmt.Errorf("failed to reopen staging file for commit: %w", err)
	}

	touchedPartitions := make(map[string]int64) // namespace -> initial file size

	rollbackCommit := func() error {
		var errs []error
		for ns, origOffset := range touchedPartitions {
			if err := d.filePool.truncateAndReset(ns, origOffset); err != nil {
				d.unrestoredPartitions[ns] = origOffset
				errs = append(errs, fmt.Errorf("failed rollback for partition %s: %w", ns, err))
			} else {
				delete(d.unrestoredPartitions, ns)
			}
		}
		if len(errs) > 0 {
			d.rollbackErr = errors.Join(errs...)
			return d.rollbackErr
		}
		d.rollbackErr = nil
		return nil
	}

	handleCommitError := func(initiatingErr error) error {
		_ = stagingReadFile.Close()
		if rbErr := rollbackCommit(); rbErr != nil {
			return errors.Join(initiatingErr, fmt.Errorf("atomic rollback failed: %w", rbErr))
		}
		return initiatingErr
	}

	scanner := bufio.NewScanner(stagingReadFile)
	scanner.Buffer(make([]byte, 64*1024), maxScannerCapacity)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return handleCommitError(err)
		}

		lineBytes := scanner.Bytes()
		if len(lineBytes) == 0 {
			continue
		}

		var rec record
		if err := json.Unmarshal(lineBytes, &rec); err != nil {
			return handleCommitError(fmt.Errorf("corrupted staging record during commit of GVR %s: %w", gvr, err))
		}

		if _, ok := touchedPartitions[rec.Namespace]; !ok {
			safeName := safeNamespaceFilename(rec.Namespace)
			path := filepath.Join(d.partitionsDir, safeName)
			var initialSize int64
			if info, err := os.Stat(path); err == nil {
				initialSize = info.Size()
			} else if !os.IsNotExist(err) {
				return handleCommitError(fmt.Errorf("failed to stat partition for namespace %s: %w", rec.Namespace, err))
			}
			touchedPartitions[rec.Namespace] = initialSize
		}

		writer, err := d.filePool.getWriter(rec.Namespace)
		if err != nil {
			return handleCommitError(err)
		}

		if _, err := writer.Write(lineBytes); err != nil {
			if isDiskFull(err) {
				return handleCommitError(fmt.Errorf("%w: %v", ErrDiskFull, err))
			}
			return handleCommitError(fmt.Errorf("failed to write record for resource %s to namespace %s: %w", rec.ID, rec.Namespace, err))
		}
		if err := writer.WriteByte('\n'); err != nil {
			if isDiskFull(err) {
				return handleCommitError(fmt.Errorf("%w: %v", ErrDiskFull, err))
			}
			return handleCommitError(fmt.Errorf("failed to write delimiter for resource %s to namespace %s: %w", rec.ID, rec.Namespace, err))
		}
	}

	if err := scanner.Err(); err != nil {
		return handleCommitError(fmt.Errorf("failed reading staging file for GVR %s: %w", gvr, err))
	}

	if err := ctx.Err(); err != nil {
		return handleCommitError(err)
	}

	// Flush all touched partition writers to ensure committed records are durably written
	for ns := range touchedPartitions {
		pw, err := d.filePool.getPooledWriter(ns)
		if err != nil {
			return handleCommitError(err)
		}
		if err := pw.writer.Flush(); err != nil {
			if isDiskFull(err) {
				return handleCommitError(fmt.Errorf("%w: %v", ErrDiskFull, err))
			}
			return handleCommitError(fmt.Errorf("failed to flush partition for namespace %s: %w", ns, err))
		}
	}

	if err := ctx.Err(); err != nil {
		return handleCommitError(err)
	}

	_ = stagingReadFile.Close()
	_ = os.Remove(d.stagingPath)

	for ns, count := range d.stagingCounts {
		d.committedCounts[ns] += count
		d.namespaces[ns] = struct{}{}
		d.totalResources += count
	}

	d.resetStaging()
	return nil
}

func (d *DiskStore) RollbackGVR(ctx context.Context, gvr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}
	if d.sealed {
		return ErrStoreSealed
	}
	if d.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if d.activeGVR != gvr {
		return ErrMismatchedGVR
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if d.stagingWriter != nil {
		_ = d.stagingWriter.Flush()
	}
	if d.stagingFile != nil {
		_ = d.stagingFile.Close()
	}
	if d.stagingPath != "" {
		_ = os.Remove(d.stagingPath)
	}

	// Attempt recovery of any unrestored partitions
	if len(d.unrestoredPartitions) > 0 {
		var rollbackErrs []error
		for ns, origOffset := range d.unrestoredPartitions {
			if err := d.filePool.truncateAndReset(ns, origOffset); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("failed to recover partition %s: %w", ns, err))
			} else {
				delete(d.unrestoredPartitions, ns)
			}
		}
		if len(d.unrestoredPartitions) > 0 {
			d.rollbackErr = errors.Join(rollbackErrs...)
			return fmt.Errorf("%w: %v", ErrStoreCorrupted, d.rollbackErr)
		}
		d.rollbackErr = nil
	}

	d.resetStaging()
	return nil
}

func (d *DiskStore) resetStaging() {
	d.activeGVR = ""
	d.stagingFile = nil
	d.stagingWriter = nil
	d.stagingPath = ""
	d.stagingCounts = make(map[string]int)
}

func (d *DiskStore) Seal(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}
	if len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return fmt.Errorf("%w: cannot seal store with unrestored rollback failures: %v", ErrStoreCorrupted, d.rollbackErr)
	}
	if d.sealed {
		return nil
	}
	if d.activeGVR != "" {
		return ErrGVRAlreadyActive
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Close all partition files in the file pool to ensure all bytes are synced to disk
	if err := d.filePool.closeAll(); err != nil {
		return err
	}

	d.sealed = true
	return nil
}

func (d *DiskStore) Namespaces() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || !d.sealed || len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return nil
	}

	nsList := slices.Sorted(maps.Keys(d.namespaces))
	return nsList
}

func (d *DiskStore) NamespaceCounts() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return nil
	}

	counts := make(map[string]int, len(d.committedCounts))
	maps.Copy(counts, d.committedCounts)
	return counts
}

func (d *DiskStore) TotalResources() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return 0
	}

	return d.totalResources
}

func (d *DiskStore) LoadBatch(ctx context.Context, namespace string) (*cautils.ResourceBatch, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, ErrStoreClosed
	}
	if len(d.unrestoredPartitions) > 0 || d.rollbackErr != nil {
		return nil, fmt.Errorf("%w: cannot load batch from store with unrestored rollback failures: %v", ErrStoreCorrupted, d.rollbackErr)
	}
	if !d.sealed {
		return nil, ErrStoreNotSealed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, ok := d.namespaces[namespace]; !ok {
		return nil, ErrNamespaceNotFound
	}

	safeName := safeNamespaceFilename(namespace)
	path := filepath.Join(d.partitionsDir, safeName)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNamespaceNotFound
		}
		return nil, fmt.Errorf("failed to open partition file for namespace %s: %w", namespace, err)
	}
	defer file.Close()

	batch := cautils.NewResourceBatch(namespace)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxScannerCapacity)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		lineBytes := scanner.Bytes()
		if len(lineBytes) == 0 {
			continue
		}

		var rec record
		if err := json.Unmarshal(lineBytes, &rec); err != nil {
			return nil, fmt.Errorf("corrupted partition data for namespace %s: %w", namespace, err)
		}

		metaObj, err := rec.toMetadata()
		if err != nil {
			return nil, err
		}

		batch.K8SResources[rec.GVR] = append(batch.K8SResources[rec.GVR], rec.ID)
		batch.AllResources[rec.ID] = metaObj
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading partition for namespace %s: %w", namespace, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if d.opts.PurgeOnLoad {
		_ = file.Close()
		if d.filePool != nil {
			_ = d.filePool.closeAndRemove(namespace)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to purge partition file for namespace %s: %w", namespace, err)
		}
		d.purgeNamespaceAccountingLocked(namespace)
	}

	return batch, nil
}

func (d *DiskStore) PurgeNamespace(namespace string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStoreClosed
	}

	if d.filePool != nil {
		if err := d.filePool.closeAndRemove(namespace); err != nil {
			return fmt.Errorf("failed closing partition writer for namespace %s: %w", namespace, err)
		}
	}

	safeName := safeNamespaceFilename(namespace)
	path := filepath.Join(d.partitionsDir, safeName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to purge partition file for namespace %s: %w", namespace, err)
	}
	d.purgeNamespaceAccountingLocked(namespace)
	delete(d.unrestoredPartitions, namespace)
	if len(d.unrestoredPartitions) == 0 {
		d.rollbackErr = nil
	}
	return nil
}

func (d *DiskStore) purgeNamespaceAccountingLocked(namespace string) {
	count, exists := d.committedCounts[namespace]
	if !exists {
		return
	}
	delete(d.namespaces, namespace)
	delete(d.committedCounts, namespace)
	d.totalResources -= count
}

func (d *DiskStore) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	var firstErr error

	if d.stagingWriter != nil {
		if err := d.stagingWriter.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.stagingFile != nil {
		if err := d.stagingFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if d.filePool != nil {
		if err := d.filePool.closeAll(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if d.rootDir != "" {
		if err := os.RemoveAll(d.rootDir); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to remove spill root directory %s: %w", d.rootDir, err)
			}
			return firstErr
		}
	}

	d.closed = true
	d.stagingCounts = nil
	d.committedCounts = nil
	d.namespaces = nil
	d.unrestoredPartitions = nil
	d.rollbackErr = nil
	return firstErr
}

// safeNamespaceFilename generates a safe, collision-free filename from a namespace name.
func safeNamespaceFilename(namespace string) string {
	return hex.EncodeToString([]byte(namespace)) + ".jsonl"
}

// isDiskFull inspects an error to detect if disk space is exhausted.
func isDiskFull(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOSPC) {
		return true
	}
	str := strings.ToLower(err.Error())
	return strings.Contains(str, "no space left on device") || strings.Contains(str, "disk full")
}

// fdPool manages an LRU cache of open partition file writers.
type fdPool struct {
	baseDir    string
	maxOpen    int
	bufferSize int
	pool       map[string]*list.Element // safeFilename -> *list.Element(*pooledWriter)
	lru        *list.List
}

type pooledWriter struct {
	file   *os.File
	writer *bufio.Writer
	name   string
}

func newFDPool(baseDir string, maxOpen, bufferSize int) *fdPool {
	return &fdPool{
		baseDir:    baseDir,
		maxOpen:    maxOpen,
		bufferSize: bufferSize,
		pool:       make(map[string]*list.Element),
		lru:        list.New(),
	}
}

func (p *fdPool) getWriter(namespace string) (*bufio.Writer, error) {
	safeName := safeNamespaceFilename(namespace)

	if elem, ok := p.pool[safeName]; ok {
		p.lru.MoveToFront(elem)
		return elem.Value.(*pooledWriter).writer, nil
	}

	// Evict oldest if pool is at capacity
	if p.lru.Len() >= p.maxOpen {
		if err := p.evictOldest(); err != nil {
			return nil, err
		}
	}

	path := filepath.Join(p.baseDir, safeName)
	// ALWAYS open in APPEND mode so evicted files are never truncated on reopen
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		if isDiskFull(err) {
			return nil, fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return nil, fmt.Errorf("failed to open partition file %s: %w", safeName, err)
	}

	writer := bufio.NewWriterSize(file, p.bufferSize)
	pw := &pooledWriter{file: file, writer: writer, name: safeName}
	elem := p.lru.PushFront(pw)
	p.pool[safeName] = elem
	return writer, nil
}

func (p *fdPool) getPooledWriter(namespace string) (*pooledWriter, error) {
	safeName := safeNamespaceFilename(namespace)
	if elem, ok := p.pool[safeName]; ok {
		p.lru.MoveToFront(elem)
		return elem.Value.(*pooledWriter), nil
	}
	if _, err := p.getWriter(namespace); err != nil {
		return nil, err
	}
	elem := p.pool[safeName]
	return elem.Value.(*pooledWriter), nil
}

func (p *fdPool) truncateAndReset(namespace string, origOffset int64) error {
	safeName := safeNamespaceFilename(namespace)
	path := filepath.Join(p.baseDir, safeName)

	if elem, ok := p.pool[safeName]; ok {
		pw := elem.Value.(*pooledWriter)
		pw.writer.Reset(pw.file)
		if origOffset == 0 {
			var errs []error
			if err := pw.file.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed closing partition file %s: %w", namespace, err))
			}
			p.lru.Remove(elem)
			delete(p.pool, safeName)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("failed removing partition file %s: %w", namespace, err))
			}
			return errors.Join(errs...)
		}
		var errs []error
		if err := pw.file.Truncate(origOffset); err != nil {
			errs = append(errs, fmt.Errorf("failed truncating partition file %s: %w", namespace, err))
		}
		if _, err := pw.file.Seek(origOffset, io.SeekStart); err != nil {
			errs = append(errs, fmt.Errorf("failed seeking partition file %s: %w", namespace, err))
		}
		if len(errs) > 0 {
			if err := pw.file.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed closing partition file %s after failed truncate: %w", namespace, err))
			}
			p.lru.Remove(elem)
			delete(p.pool, safeName)
			return errors.Join(errs...)
		}
		return nil
	}

	// File not in active pool
	if origOffset == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed removing partition file %s: %w", namespace, err)
		}
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed opening partition file %s for rollback: %w", namespace, err)
	}
	var errs []error
	if err := f.Truncate(origOffset); err != nil {
		errs = append(errs, fmt.Errorf("failed truncating partition file %s: %w", namespace, err))
	}
	if err := f.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed closing partition file %s: %w", namespace, err))
	}
	return errors.Join(errs...)
}

func (p *fdPool) closeAndRemove(namespace string) error {
	safeName := safeNamespaceFilename(namespace)
	if elem, ok := p.pool[safeName]; ok {
		pw := elem.Value.(*pooledWriter)
		p.lru.Remove(elem)
		delete(p.pool, safeName)

		var firstErr error
		if pw.file != nil {
			if err := pw.file.Close(); err != nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return nil
}

func (p *fdPool) evictOldest() error {
	back := p.lru.Back()
	if back == nil {
		return nil
	}

	pw := back.Value.(*pooledWriter)
	if err := pw.writer.Flush(); err != nil {
		if isDiskFull(err) {
			return fmt.Errorf("%w: %v", ErrDiskFull, err)
		}
		return fmt.Errorf("failed flushing evicted partition %s: %w", pw.name, err)
	}

	if pw.file != nil {
		if err := pw.file.Close(); err != nil {
			return fmt.Errorf("failed closing evicted partition %s: %w", pw.name, err)
		}
	}

	p.lru.Remove(back)
	delete(p.pool, pw.name)
	return nil
}

func (p *fdPool) closeAll() error {
	var firstErr error
	var failedWriters []*pooledWriter

	for elem := p.lru.Front(); elem != nil; elem = elem.Next() {
		pw := elem.Value.(*pooledWriter)
		if err := pw.writer.Flush(); err != nil {
			if firstErr == nil {
				if isDiskFull(err) {
					firstErr = fmt.Errorf("%w: %v", ErrDiskFull, err)
				} else {
					firstErr = err
				}
			}
			failedWriters = append(failedWriters, pw)
			continue
		}
		if pw.file != nil {
			if err := pw.file.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	if len(failedWriters) == 0 {
		p.pool = make(map[string]*list.Element)
		p.lru.Init()
	} else {
		// Retain failed writers in the pool so Seal/Close can be retried
		p.pool = make(map[string]*list.Element)
		p.lru.Init()
		for _, pw := range failedWriters {
			elem := p.lru.PushBack(pw)
			p.pool[pw.name] = elem
		}
	}

	return firstErr
}

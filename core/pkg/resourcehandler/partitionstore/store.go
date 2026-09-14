package partitionstore

import (
	"context"
	"errors"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

var (
	// ErrStoreSealed is returned when a write operation is attempted after Seal() has been called.
	ErrStoreSealed = errors.New("partition store is sealed")

	// ErrStoreNotSealed is returned when LoadBatch is called before Seal() has been called.
	ErrStoreNotSealed = errors.New("partition store is not sealed")

	// ErrStoreClosed is returned when any operation is attempted after Close() has been called.
	ErrStoreClosed = errors.New("partition store is closed")

	// ErrNoActiveGVR is returned when Put is called without an active BeginGVR transaction.
	ErrNoActiveGVR = errors.New("no active GVR transaction (call BeginGVR first)")

	// ErrGVRAlreadyActive is returned when BeginGVR is called while another GVR transaction is in progress.
	ErrGVRAlreadyActive = errors.New("another GVR transaction is already active")

	// ErrMismatchedGVR is returned when CommitGVR or RollbackGVR is called with a GVR that does not match the active transaction.
	ErrMismatchedGVR = errors.New("specified GVR does not match the active transaction")

	// ErrNamespaceNotFound is returned when LoadBatch is called for a namespace that contains no stored resources.
	ErrNamespaceNotFound = errors.New("namespace not found in partition store")

	// ErrDiskFull is returned when disk spill operations fail due to exhausted disk space (ENOSPC).
	ErrDiskFull = errors.New("spill store ran out of disk space (ENOSPC)")

	// ErrStoreCorrupted is returned when partition store operations are attempted on a store with unrecovered rollback failures.
	ErrStoreCorrupted = errors.New("partition store is corrupted due to unrecovered rollback failure")
)

// Store defines the lifecycle and storage interface for scan-scoped namespaced Kubernetes resources.
type Store interface {
	// BeginGVR starts a staging transaction for the specified GVR.
	BeginGVR(ctx context.Context, gvr string) error

	// Put writes a namespaced object under the currently active GVR.
	// Returns ErrNoActiveGVR if no transaction is active.
	Put(ctx context.Context, namespace string, obj workloadinterface.IMetadata) error

	// CommitGVR promotes all staged objects for the active GVR to their namespace partitions.
	CommitGVR(ctx context.Context, gvr string) error

	// RollbackGVR discards all staged objects for the active GVR without touching committed partitions.
	RollbackGVR(ctx context.Context, gvr string) error

	// Seal finalizes ingestion; no further writes or commits are allowed.
	Seal(ctx context.Context) error

	// Namespaces returns a sorted slice of all namespaces holding committed resources.
	// Only valid after Seal().
	Namespaces() []string

	// NamespaceCounts returns accumulated scannable resource counts per namespace.
	// Valid after Seal().
	NamespaceCounts() map[string]int

	// TotalResources returns the total count of namespaced resources stored.
	TotalResources() int

	// LoadBatch deserializes and returns a *cautils.ResourceBatch for the specified namespace.
	// By default, this is idempotent and does not delete the partition from disk.
	LoadBatch(ctx context.Context, namespace string) (*cautils.ResourceBatch, error)

	// PurgeNamespace explicitly removes the partition for a namespace after processing to free disk/memory.
	PurgeNamespace(namespace string) error

	// Close releases all open resources and idempotently removes all temporary spill files and directories.
	Close() error
}

// Options configures partition store behavior.
type Options struct {
	// BaseDir is the directory in which temporary spill directories are created.
	// If empty, os.TempDir() is used.
	BaseDir string

	// MaxOpenFiles is the maximum number of open file descriptors in the LRU pool (DiskStore only).
	// Defaults to 64.
	MaxOpenFiles int

	// FileBufferSize is the buffer size in bytes for buffered writers.
	// Defaults to 64KB (65536).
	FileBufferSize int

	// PurgeOnLoad configures LoadBatch to automatically purge the namespace partition upon loading.
	// Defaults to false.
	PurgeOnLoad bool
}

// Option is a functional option for configuring a Store.
type Option func(*Options)

// WithBaseDir sets the base directory for disk spilling.
func WithBaseDir(dir string) Option {
	return func(o *Options) {
		o.BaseDir = dir
	}
}

// WithMaxOpenFiles sets the maximum number of open file descriptors in the pool.
func WithMaxOpenFiles(max int) Option {
	return func(o *Options) {
		if max > 0 {
			o.MaxOpenFiles = max
		}
	}
}

// WithFileBufferSize sets the writer buffer size.
func WithFileBufferSize(size int) Option {
	return func(o *Options) {
		if size > 0 {
			o.FileBufferSize = size
		}
	}
}

// WithPurgeOnLoad sets whether LoadBatch automatically purges the loaded namespace partition.
func WithPurgeOnLoad(purge bool) Option {
	return func(o *Options) {
		o.PurgeOnLoad = purge
	}
}

func defaultOptions() Options {
	return Options{
		BaseDir:        "",
		MaxOpenFiles:   64,
		FileBufferSize: 64 * 1024, // 64 KB
		PurgeOnLoad:    false,
	}
}

package partitionstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskStore_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX permission test on Windows")
	}
	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	// Check root directory permissions: 0700
	info, err := os.Stat(store.RootDir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "root spill directory must be owner-only (0700)")

	// Ingest objects to produce partition files
	ctx := context.Background()
	pod := createTestObject("pod-1", "ns-secure", "Pod")

	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-secure", pod))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))
	require.NoError(t, store.Seal(ctx))

	// Check partition file permissions: 0600
	partitionsDir := filepath.Join(store.RootDir(), "partitions")
	entries, err := os.ReadDir(partitionsDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		fInfo, err := entry.Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fInfo.Mode().Perm(), "partition file %s must be owner-only (0600)", entry.Name())
	}
}

func TestDiskStore_FDEvictionAndReopenWithoutTruncation(t *testing.T) {
	// Configure pool with tiny maxOpen capacity to force frequent evictions
	store, err := NewDiskStore(WithMaxOpenFiles(4))
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	numNamespaces := 20

	// GVR 1: write to all 20 namespaces (forces 16 evictions)
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	for i := range numNamespaces {
		ns := fmt.Sprintf("ns-%02d", i)
		pod := createTestObject(fmt.Sprintf("pod-%d", i), ns, "Pod")
		require.NoError(t, store.Put(ctx, ns, pod))
	}
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// GVR 2: write again to the same 20 namespaces (forces re-opening of previously evicted files)
	require.NoError(t, store.BeginGVR(ctx, "v1/services"))
	for i := range numNamespaces {
		ns := fmt.Sprintf("ns-%02d", i)
		svc := createTestObject(fmt.Sprintf("svc-%d", i), ns, "Service")
		require.NoError(t, store.Put(ctx, ns, svc))
	}
	require.NoError(t, store.CommitGVR(ctx, "v1/services"))

	require.NoError(t, store.Seal(ctx))

	// Verify all 20 namespaces contain BOTH objects
	for i := range numNamespaces {
		ns := fmt.Sprintf("ns-%02d", i)
		batch, err := store.LoadBatch(ctx, ns)
		require.NoError(t, err, "failed loading namespace %s", ns)
		assert.Len(t, batch.AllResources, 2, "namespace %s should contain both Pod and Service without truncation", ns)
		assert.Len(t, batch.K8SResources["v1/pods"], 1)
		assert.Len(t, batch.K8SResources["v1/services"], 1)
	}
}

func TestDiskStore_IdempotentLeakFreeClose(t *testing.T) {
	store, err := NewDiskStore()
	require.NoError(t, err)

	rootDir := store.RootDir()
	info, err := os.Stat(rootDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	ctx := context.Background()
	pod := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// First Close deletes directory
	require.NoError(t, store.Close())

	_, err = os.Stat(rootDir)
	assert.True(t, os.IsNotExist(err), "root spill dir must be removed on Close()")

	// Second Close is idempotent
	require.NoError(t, store.Close())
}

func TestDiskStore_PurgeOnLoadOption(t *testing.T) {
	store, err := NewDiskStore(WithPurgeOnLoad(true))
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	pod := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))
	require.NoError(t, store.Seal(ctx))

	// First load succeeds and purges
	batch, err := store.LoadBatch(ctx, "ns-a")
	require.NoError(t, err)
	assert.Len(t, batch.AllResources, 1)

	// Second load fails with ErrNamespaceNotFound because it was purged
	_, err = store.LoadBatch(ctx, "ns-a")
	assert.ErrorIs(t, err, ErrNamespaceNotFound)
}

func TestDiskStore_IsDiskFullDetection(t *testing.T) {
	assert.True(t, isDiskFull(syscall.ENOSPC))
	assert.True(t, isDiskFull(fmt.Errorf("disk write failed: %w", syscall.ENOSPC)))
	assert.True(t, isDiskFull(errors.New("write error: no space left on device")))
	assert.True(t, isDiskFull(errors.New("disk full while writing payload")))
	assert.False(t, isDiskFull(errors.New("permission denied")))
	assert.False(t, isDiskFull(nil))
}

func TestDiskStore_ENOSPC_Simulation(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("skipping /dev/full test; device not available")
	}
	devFull, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("skipping /dev/full test; cannot open /dev/full")
	}
	defer devFull.Close()

	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))

	// Replace staging writer with unbuffered writer targeting /dev/full
	store.stagingWriter = bufio.NewWriterSize(devFull, 1)
	pod := createTestObject("pod-full", "ns-a", "Pod")
	err = store.Put(ctx, "ns-a", pod)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDiskFull)
	assert.False(t, strings.Contains(err.Error(), "secret-key"))
	assert.False(t, strings.Contains(err.Error(), "super-sensitive-token"))
	assert.False(t, strings.Contains(err.Error(), "secret-value-12345"))
}

type countCancelContext struct {
	context.Context
	checkCount int
	cancelAt   int
	doneCh     chan struct{}
	err        error
}

func newCountCancelContext(parent context.Context, cancelAt int) *countCancelContext {
	return &countCancelContext{
		Context:  parent,
		cancelAt: cancelAt,
		doneCh:   make(chan struct{}),
	}
}

func (c *countCancelContext) Err() error {
	c.checkCount++
	if c.checkCount >= c.cancelAt {
		if c.err == nil {
			c.err = context.Canceled
			close(c.doneCh)
		}
		return c.err
	}
	return c.Context.Err()
}

func (c *countCancelContext) Done() <-chan struct{} {
	return c.doneCh
}

type hookCancelContext struct {
	context.Context
	checkCount int
	triggerAt  int
	onTrigger  func()
	doneCh     chan struct{}
	err        error
}

func newHookCancelContext(parent context.Context, triggerAt int, onTrigger func()) *hookCancelContext {
	return &hookCancelContext{
		Context:   parent,
		triggerAt: triggerAt,
		onTrigger: onTrigger,
		doneCh:    make(chan struct{}),
	}
}

func (c *hookCancelContext) Err() error {
	c.checkCount++
	if c.checkCount >= c.triggerAt {
		if c.err == nil {
			if c.onTrigger != nil {
				c.onTrigger()
			}
			c.err = context.Canceled
			close(c.doneCh)
		}
		return c.err
	}
	return c.Context.Err()
}

func (c *hookCancelContext) Done() <-chan struct{} {
	return c.doneCh
}

func TestDiskStore_CommitGVR_AtomicRollbackOnFailure(t *testing.T) {
	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Commit 1 pod in ns-a successfully
	pod1 := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod1))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// Stage 2nd GVR with 600 pods (300 in ns-a, 300 in ns-b)
	// so the periodic lineCount % 500 check in CommitGVR triggers mid-write
	require.NoError(t, store.BeginGVR(ctx, "v1/pods-batch2"))
	for i := range 300 {
		require.NoError(t, store.Put(ctx, "ns-a", createTestObject(fmt.Sprintf("pod-a-%d", i), "ns-a", "Pod")))
		require.NoError(t, store.Put(ctx, "ns-b", createTestObject(fmt.Sprintf("pod-b-%d", i), "ns-b", "Pod")))
	}

	// Use countCancelContext: cancelAt=50 so initial ctx.Err() passes, several records are written to ns-a and ns-b,
	// and then ctx.Err() cancels mid-stream during scanning
	cancelCtx := newCountCancelContext(ctx, 50)
	err = store.CommitGVR(cancelCtx, "v1/pods-batch2")
	require.ErrorIs(t, err, context.Canceled)

	// Rollback the failed transaction to close staging file and reset active GVR
	require.NoError(t, store.RollbackGVR(ctx, "v1/pods-batch2"))

	// Now Seal and verify ns-a still has ONLY pod-1 (the 300 pods were truncated), and ns-b was cleaned up completely
	require.NoError(t, store.Seal(ctx))
	batchA, err := store.LoadBatch(ctx, "ns-a")
	require.NoError(t, err)
	assert.Len(t, batchA.AllResources, 1)
	assert.Equal(t, "pod-1", batchA.AllResources[pod1.GetID()].GetName())

	_, err = store.LoadBatch(ctx, "ns-b")
	assert.ErrorIs(t, err, ErrNamespaceNotFound)

	// Assert physical cleanup of newly created partition file on disk
	nsBPartitionPath := filepath.Join(store.RootDir(), "partitions", safeNamespaceFilename("ns-b"))
	_, statErr := os.Stat(nsBPartitionPath)
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "newly created partition for ns-b must be physically removed on rollback")

	// Assert temporary staging file is cleaned up on disk
	stagingEntries, err := os.ReadDir(filepath.Join(store.RootDir(), "staging"))
	require.NoError(t, err)
	assert.Empty(t, stagingEntries, "temporary staging files must be removed on rollback")
}

func TestDiskStore_CommitGVR_PostScanCancellation(t *testing.T) {
	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	for i := range 10 {
		require.NoError(t, store.Put(ctx, "ns-a", createTestObject(fmt.Sprintf("pod-%d", i), "ns-a", "Pod")))
	}

	// 1 initial check at CommitGVR entry + 10 per-iteration checks + 1 post-scan check = 12
	cancelCtx := newCountCancelContext(ctx, 12)
	err = store.CommitGVR(cancelCtx, "v1/pods")
	require.ErrorIs(t, err, context.Canceled)

	require.NoError(t, store.RollbackGVR(ctx, "v1/pods"))
	require.NoError(t, store.Seal(ctx))

	// Verify nothing was published
	assert.Empty(t, store.Namespaces())
	assert.Zero(t, store.TotalResources())

	// Assert physical cleanup of temporary partition file on disk
	nsAPartitionPath := filepath.Join(store.RootDir(), "partitions", safeNamespaceFilename("ns-a"))
	_, statErr := os.Stat(nsAPartitionPath)
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "partition for ns-a must be physically removed on rollback")

	// Assert temporary staging file is cleaned up on disk
	stagingEntriesA, err := os.ReadDir(filepath.Join(store.RootDir(), "staging"))
	require.NoError(t, err)
	assert.Empty(t, stagingEntriesA, "temporary staging files must be removed on rollback")
}

func TestDiskStore_LoadBatch_Cancellation(t *testing.T) {
	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	for i := range 10 {
		require.NoError(t, store.Put(ctx, "ns-a", createTestObject(fmt.Sprintf("pod-%d", i), "ns-a", "Pod")))
	}
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))
	require.NoError(t, store.Seal(ctx))

	t.Run("MidScanCancellation", func(t *testing.T) {
		// 1 initial check at LoadBatch entry + 5 iterations = 6
		cancelCtx := newCountCancelContext(ctx, 6)
		batch, err := store.LoadBatch(cancelCtx, "ns-a")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, batch)
	})

	t.Run("PostScanCancellation", func(t *testing.T) {
		// 1 initial check at LoadBatch entry + 10 per-iteration checks + 1 post-scan check = 12
		cancelCtx := newCountCancelContext(ctx, 12)
		batch, err := store.LoadBatch(cancelCtx, "ns-a")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, batch)
	})
}

func TestDiskStore_PurgeNamespace_WriterDetached(t *testing.T) {
	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// GVR 1: write and commit to ns-a (ns-a pooledWriter is in fdPool)
	pod1 := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod1))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// Verify ns-a writer is in pool
	safeName := safeNamespaceFilename("ns-a")
	assert.Contains(t, store.filePool.pool, safeName)

	// Purge ns-a: must detach and remove from pool and delete file
	require.NoError(t, store.PurgeNamespace("ns-a"))
	assert.NotContains(t, store.filePool.pool, safeName)

	// Now start a new GVR and write to ns-a again
	pod2 := createTestObject("pod-2", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/services"))
	require.NoError(t, store.Put(ctx, "ns-a", pod2))
	require.NoError(t, store.CommitGVR(ctx, "v1/services"))

	require.NoError(t, store.Seal(ctx))

	// LoadBatch must successfully find and return pod2 (not ErrNamespaceNotFound)
	batch, err := store.LoadBatch(ctx, "ns-a")
	require.NoError(t, err)
	assert.Len(t, batch.AllResources, 1)
	assert.Equal(t, "pod-2", batch.AllResources[pod2.GetID()].GetName())
}

func TestDiskStore_CloseAll_Retry(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("skipping /dev/full test; device not available")
	}
	devFull, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("skipping /dev/full test; cannot open /dev/full")
	}
	defer devFull.Close()

	store, err := NewDiskStore()
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	pod := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// Manually inject a pooledWriter pointing to /dev/full with buffered bytes
	badPw := &pooledWriter{
		file:   devFull,
		writer: bufio.NewWriterSize(devFull, 1024),
		name:   "bad-pw",
	}
	_, _ = badPw.writer.WriteString("fail to flush to dev full")
	elem := store.filePool.lru.PushBack(badPw)
	store.filePool.pool["bad-pw"] = elem

	// First closeAll fails due to /dev/full
	err = store.filePool.closeAll()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDiskFull)
	assert.Contains(t, store.filePool.pool, "bad-pw", "writer that failed flush should be retained in pool for retry")

	// Fix the writer: replace its file and writer with a valid temporary file
	tempFile, err := os.CreateTemp("", "retry-test-*")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	badPw.file = tempFile
	badPw.writer = bufio.NewWriter(tempFile)
	err = store.filePool.closeAll()
	assert.NoError(t, err)
	assert.Empty(t, store.filePool.pool)
}

func TestDiskStore_CommitGVR_RollbackFailure_FaultInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping fault injection test; directory permissions do not block removal on this platform")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping fault injection test; root bypasses directory permission checks")
	}

	// Configure store with 1-byte buffer size so each record is flushed immediately
	store, err := NewDiskStore(WithFileBufferSize(1))
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Ingest and commit 1 pod in ns-clean
	pod1 := createTestObject("pod-1", "ns-clean", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-clean", pod1))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))

	// Begin GVR 2 and put a record into a new namespace ns-dirty
	dirtySvc := createTestObject("svc-dirty", "ns-dirty", "Service")
	require.NoError(t, store.BeginGVR(ctx, "v1/services"))
	require.NoError(t, store.Put(ctx, "ns-dirty", dirtySvc))

	partitionsDir := filepath.Join(store.RootDir(), "partitions")
	defer func() {
		_ = os.Chmod(partitionsDir, 0o700)
	}()

	// Trigger commit with cancellation after the record has reached disk:
	// Check 1: CommitGVR entry check
	// Check 2: Loop iteration 1 check (record is written and flushed to ns-dirty partition file)
	// Check 3: Post-scan check: inject fault by making partitions directory read-only (0500)
	// so that truncateAndReset fails to remove the newly created partition file, and return context.Canceled.
	cancelCtx := newHookCancelContext(ctx, 3, func() {
		require.NoError(t, os.Chmod(partitionsDir, 0o500))
	})

	err = store.CommitGVR(cancelCtx, "v1/services")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "initiating error context.Canceled must be preserved")
	assert.True(t, strings.Contains(err.Error(), "atomic rollback failed") || strings.Contains(err.Error(), "permission denied"),
		"restoration error must be propagated and not discarded: %v", err)

	// Verify the store is marked unusable for seal and load
	sealErr := store.Seal(ctx)
	require.Error(t, sealErr)
	assert.ErrorIs(t, sealErr, ErrStoreCorrupted)

	_, loadErr := store.LoadBatch(ctx, "ns-clean")
	require.Error(t, loadErr)
	assert.ErrorIs(t, loadErr, ErrStoreCorrupted)

	// Attempting RollbackGVR while directory is still non-writable should fail and keep store corrupted
	rbErr := store.RollbackGVR(ctx, "v1/services")
	require.Error(t, rbErr)
	assert.ErrorIs(t, rbErr, ErrStoreCorrupted)

	// Restore permissions on partitions directory to allow recovery
	require.NoError(t, os.Chmod(partitionsDir, 0o700))

	// Retry RollbackGVR; recovery should now succeed
	require.NoError(t, store.RollbackGVR(ctx, "v1/services"))

	// Verify that the dirty partition file was physically removed from disk
	dirtyPartitionPath := filepath.Join(partitionsDir, safeNamespaceFilename("ns-dirty"))
	_, statErr := os.Stat(dirtyPartitionPath)
	assert.True(t, os.IsNotExist(statErr), "failed partition file must be removed after successful rollback recovery")

	// Verify store is now fully recovered and usable: commit a new GVR
	cfg := createTestObject("cfg-1", "ns-clean", "ConfigMap")
	require.NoError(t, store.BeginGVR(ctx, "v1/configmaps"))
	require.NoError(t, store.Put(ctx, "ns-clean", cfg))
	require.NoError(t, store.CommitGVR(ctx, "v1/configmaps"))

	// Seal should now succeed
	require.NoError(t, store.Seal(ctx))

	// Load ns-clean: should contain both pod-1 and cfg-1
	batchClean, err := store.LoadBatch(ctx, "ns-clean")
	require.NoError(t, err)
	assert.Len(t, batchClean.AllResources, 2)
	assert.Contains(t, batchClean.AllResources, pod1.GetID())
	assert.Contains(t, batchClean.AllResources, cfg.GetID())

	// ns-dirty should not exist
	_, err = store.LoadBatch(ctx, "ns-dirty")
	assert.ErrorIs(t, err, ErrNamespaceNotFound)
}

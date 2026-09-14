package partitionstore

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// MemoryStore is an in-memory implementation of Store that faithfully replicates
// the transactional staging, commit/rollback semantics, and lifecycle state machine.
type MemoryStore struct {
	mu              sync.Mutex
	opts            Options
	activeGVR       string
	sealed          bool
	closed          bool
	staged          map[string]map[string][]record // gvr -> namespace -> []record
	committed       map[string]map[string][]record // namespace -> gvr -> []record
	namespaceCounts map[string]int
	totalResources  int
}

// NewMemoryStore creates a new in-memory partition store.
func NewMemoryStore(opts ...Option) *MemoryStore {
	options := defaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	return &MemoryStore{
		opts:            options,
		staged:          make(map[string]map[string][]record),
		committed:       make(map[string]map[string][]record),
		namespaceCounts: make(map[string]int),
	}
}

func (m *MemoryStore) BeginGVR(ctx context.Context, gvr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}
	if m.sealed {
		return ErrStoreSealed
	}
	if m.activeGVR != "" {
		return ErrGVRAlreadyActive
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.activeGVR = gvr
	if m.staged[gvr] == nil {
		m.staged[gvr] = make(map[string][]record)
	}
	return nil
}

func (m *MemoryStore) Put(ctx context.Context, namespace string, obj workloadinterface.IMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}
	if m.sealed {
		return ErrStoreSealed
	}
	if m.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	rec := newRecord(m.activeGVR, namespace, obj)
	m.staged[m.activeGVR][namespace] = append(m.staged[m.activeGVR][namespace], rec)
	return nil
}

func (m *MemoryStore) CommitGVR(ctx context.Context, gvr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}
	if m.sealed {
		return ErrStoreSealed
	}
	if m.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if m.activeGVR != gvr {
		return ErrMismatchedGVR
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	stagedGVR := m.staged[gvr]
	for ns, records := range stagedGVR {
		if m.committed[ns] == nil {
			m.committed[ns] = make(map[string][]record)
		}
		m.committed[ns][gvr] = append(m.committed[ns][gvr], records...)
		m.namespaceCounts[ns] += len(records)
		m.totalResources += len(records)
	}

	delete(m.staged, gvr)
	m.activeGVR = ""
	return nil
}

func (m *MemoryStore) RollbackGVR(ctx context.Context, gvr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}
	if m.sealed {
		return ErrStoreSealed
	}
	if m.activeGVR == "" {
		return ErrNoActiveGVR
	}
	if m.activeGVR != gvr {
		return ErrMismatchedGVR
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	delete(m.staged, gvr)
	m.activeGVR = ""
	return nil
}

func (m *MemoryStore) Seal(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}
	if m.sealed {
		return nil
	}
	if m.activeGVR != "" {
		return ErrGVRAlreadyActive
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.sealed = true
	return nil
}

func (m *MemoryStore) Namespaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed || !m.sealed {
		return nil
	}

	nsList := slices.Sorted(maps.Keys(m.committed))
	return nsList
}

func (m *MemoryStore) NamespaceCounts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	counts := make(map[string]int, len(m.namespaceCounts))
	maps.Copy(counts, m.namespaceCounts)
	return counts
}

func (m *MemoryStore) TotalResources() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.totalResources
}

func (m *MemoryStore) LoadBatch(ctx context.Context, namespace string) (*cautils.ResourceBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrStoreClosed
	}
	if !m.sealed {
		return nil, ErrStoreNotSealed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nsRecords, ok := m.committed[namespace]
	if !ok || len(nsRecords) == 0 {
		return nil, ErrNamespaceNotFound
	}

	batch := cautils.NewResourceBatch(namespace)
	for gvr, records := range nsRecords {
		for _, rec := range records {
			metaObj, err := rec.deepCopy().toMetadata()
			if err != nil {
				return nil, err
			}
			batch.K8SResources[gvr] = append(batch.K8SResources[gvr], rec.ID)
			batch.AllResources[rec.ID] = metaObj
		}
	}

	if m.opts.PurgeOnLoad {
		delete(m.committed, namespace)
	}

	return batch, nil
}

func (m *MemoryStore) PurgeNamespace(namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	delete(m.committed, namespace)
	return nil
}

func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.staged = nil
	m.committed = nil
	m.namespaceCounts = nil
	return nil
}

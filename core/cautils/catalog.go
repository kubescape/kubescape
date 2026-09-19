package cautils

import (
	"sync"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

// ResourceCatalog provides an accessor abstraction over collected and synthesized scan resources.
// It replaces direct reads and writes to sessionObj.AllResources, decoupling rule execution and
// result aggregation from the underlying storage mechanism.
type ResourceCatalog interface {
	// Get returns the resource metadata for the given resource ID, or false if not found.
	Get(id string) (workloadinterface.IMetadata, bool)

	// Add inserts or updates a resource in the catalog.
	Add(resource workloadinterface.IMetadata)

	// AddAll inserts all resources from the given map into the catalog.
	AddAll(resources map[string]workloadinterface.IMetadata)

	// Remove deletes a resource from the catalog by ID.
	Remove(id string)

	// Len returns the total number of unique resources in the catalog.
	Len() int

	// ListIDs returns a slice of all resource IDs currently held in the catalog.
	ListIDs() []string

	// ForEach iterates over all resources in the catalog until fn returns false or all items are visited.
	ForEach(fn func(id string, resource workloadinterface.IMetadata) bool)

	// All returns a shallow snapshot map of all resources in the catalog.
	All() map[string]workloadinterface.IMetadata
}

// MapResourceCatalog is a thread-safe in-memory implementation of ResourceCatalog.
type MapResourceCatalog struct {
	mu        sync.RWMutex
	resources map[string]workloadinterface.IMetadata
}

var _ ResourceCatalog = (*MapResourceCatalog)(nil)

// NewMapResourceCatalog creates a new MapResourceCatalog. If an initial map is provided,
// the catalog manages that map directly, keeping external references (such as sessionObj.AllResources)
// synchronized for backward compatibility.
func NewMapResourceCatalog(initial ...map[string]workloadinterface.IMetadata) *MapResourceCatalog {
	var m map[string]workloadinterface.IMetadata
	if len(initial) > 0 && initial[0] != nil {
		m = initial[0]
	} else {
		m = make(map[string]workloadinterface.IMetadata)
	}
	return &MapResourceCatalog{
		resources: m,
	}
}

// Get returns the resource metadata for the given resource ID, or false if not found.
func (c *MapResourceCatalog) Get(id string) (workloadinterface.IMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, ok := c.resources[id]
	return res, ok
}

// Add inserts or updates a resource in the catalog.
func (c *MapResourceCatalog) Add(resource workloadinterface.IMetadata) {
	if resource == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources[resource.GetID()] = resource
}

// AddAll inserts all non-nil resources from the given map into the catalog.
func (c *MapResourceCatalog) AddAll(resources map[string]workloadinterface.IMetadata) {
	if len(resources) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range resources {
		if v != nil {
			c.resources[k] = v
		}
	}
}

// Remove deletes a resource from the catalog by ID.
func (c *MapResourceCatalog) Remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.resources, id)
}

// Len returns the total number of unique resources in the catalog.
func (c *MapResourceCatalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.resources)
}

// ListIDs returns a slice of all resource IDs currently held in the catalog.
func (c *MapResourceCatalog) ListIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ids := make([]string, 0, len(c.resources))
	for id := range c.resources {
		ids = append(ids, id)
	}
	return ids
}

// ForEach iterates over all resources in the catalog until fn returns false or all items are visited.
func (c *MapResourceCatalog) ForEach(fn func(id string, resource workloadinterface.IMetadata) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for id, res := range c.resources {
		if !fn(id, res) {
			break
		}
	}
}

// All returns a shallow snapshot map of all resources in the catalog.
func (c *MapResourceCatalog) All() map[string]workloadinterface.IMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := make(map[string]workloadinterface.IMetadata, len(c.resources))
	for k, v := range c.resources {
		snapshot[k] = v
	}
	return snapshot
}

package partitionstore

import (
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"k8s.io/apimachinery/pkg/runtime"
)

// record represents a single stored Kubernetes resource serialized in JSON Lines format.
type record struct {
	ID        string         `json:"id"`
	GVR       string         `json:"gvr"`
	Namespace string         `json:"namespace"`
	Object    map[string]any `json:"object"`
}

func newRecord(gvr string, namespace string, obj workloadinterface.IMetadata) record {
	var objMap map[string]any
	var id string
	if obj != nil {
		id = obj.GetID()
		objMap = runtime.DeepCopyJSON(obj.GetObject())
	}
	return record{
		ID:        id,
		GVR:       gvr,
		Namespace: namespace,
		Object:    objMap,
	}
}

// newRecordForMarshal constructs a record referencing the object map directly.
// This is safe for immediate serialization (such as in DiskStore.Put) because
// json.Marshal performs read-only operations and the record is not retained in memory.
func newRecordForMarshal(gvr string, namespace string, obj workloadinterface.IMetadata) record {
	var objMap map[string]any
	var id string
	if obj != nil {
		id = obj.GetID()
		objMap = obj.GetObject()
	}
	return record{
		ID:        id,
		GVR:       gvr,
		Namespace: namespace,
		Object:    objMap,
	}
}

func (r record) toMetadata() (workloadinterface.IMetadata, error) {
	metaObj := objectsenvelopes.NewObject(r.Object)
	if metaObj == nil {
		return nil, fmt.Errorf("failed to decode object envelope for resource ID %s in namespace %s", r.ID, r.Namespace)
	}
	return metaObj, nil
}

// deepCopy returns an independent copy of the record with a deep-copied Object map.
func (r record) deepCopy() record {
	return record{
		ID:        r.ID,
		GVR:       r.GVR,
		Namespace: r.Namespace,
		Object:    runtime.DeepCopyJSON(r.Object),
	}
}

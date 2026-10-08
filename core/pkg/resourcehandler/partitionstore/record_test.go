package partitionstore

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRecord_Isolation(t *testing.T) {
	obj := createTestObject("test-pod", "default", "Pod")
	origMap := obj.GetObject()

	rec := newRecord("v1/pods", "default", obj)
	assert.Equal(t, obj.GetID(), rec.ID)
	assert.Equal(t, "v1/pods", rec.GVR)
	assert.Equal(t, "default", rec.Namespace)

	// Verify deep copy: maps must be equal in content but point to different memory
	assert.Equal(t, origMap, rec.Object)
	origPtr := reflect.ValueOf(origMap).Pointer()
	recPtr := reflect.ValueOf(rec.Object).Pointer()
	assert.NotEqual(t, origPtr, recPtr, "newRecord should allocate an independent deep copy of the map")

	// Mutate original object map; rec.Object must remain unchanged
	origMap["mutated"] = true
	assert.NotContains(t, rec.Object, "mutated", "mutations to source object should not affect newRecord")
}

func TestNewRecordForMarshal_ZeroCopy(t *testing.T) {
	obj := createTestObject("test-pod", "default", "Pod")
	origMap := obj.GetObject()

	rec := newRecordForMarshal("v1/pods", "default", obj)
	assert.Equal(t, obj.GetID(), rec.ID)
	assert.Equal(t, "v1/pods", rec.GVR)
	assert.Equal(t, "default", rec.Namespace)

	// Verify zero-copy: rec.Object must directly share the original map pointer
	origPtr := reflect.ValueOf(origMap).Pointer()
	recPtr := reflect.ValueOf(rec.Object).Pointer()
	assert.Equal(t, origPtr, recPtr, "newRecordForMarshal must reference the original map directly without deep copy")
}

func TestNewRecordForMarshal_SerializationParity(t *testing.T) {
	obj := createTestObject("test-workload", "prod", "Deployment")

	deepCopiedRecord := newRecord("apps/v1/deployments", "prod", obj)
	marshalRecord := newRecordForMarshal("apps/v1/deployments", "prod", obj)

	deepBytes, err := json.Marshal(deepCopiedRecord)
	require.NoError(t, err)

	marshalBytes, err := json.Marshal(marshalRecord)
	require.NoError(t, err)

	assert.JSONEq(t, string(deepBytes), string(marshalBytes), "both record constructors must produce identical JSON serialization")
}

func TestRecord_DeepCopy(t *testing.T) {
	obj := createTestObject("pod-dc", "kube-system", "Pod")
	rec := newRecordForMarshal("v1/pods", "kube-system", obj)

	copied := rec.deepCopy()
	assert.Equal(t, rec.ID, copied.ID)
	assert.Equal(t, rec.GVR, copied.GVR)
	assert.Equal(t, rec.Namespace, copied.Namespace)
	assert.Equal(t, rec.Object, copied.Object)

	recPtr := reflect.ValueOf(rec.Object).Pointer()
	copiedPtr := reflect.ValueOf(copied.Object).Pointer()
	assert.NotEqual(t, recPtr, copiedPtr, "deepCopy must create a new map instance")
}

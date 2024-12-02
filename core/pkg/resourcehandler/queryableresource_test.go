package resourcehandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
)

func TestString(t *testing.T) {
	tt := []struct {
		name   string
		input  QueryableResource
		output string
	}{
		{
			name:   "Empty field selectors",
			input:  QueryableResource{GroupVersionResourceTriplet: "/v1/pods", FieldSelectors: ""},
			output: "/v1/pods",
		},
		{
			name:   "Non-empty field selectors",
			input:  QueryableResource{GroupVersionResourceTriplet: "/v1/pods", FieldSelectors: "fs1"},
			output: "/v1/pods/fs1",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.input.String()
			if result != tc.output {
				t.Errorf("Expected: %s, got: %s", tc.output, result)
			}
		})
	}
}

func TestCopy(t *testing.T) {
	rsrc := &QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1"}
	copy := rsrc.Copy()

	if copy != *rsrc {
		t.Errorf("Expected: %v, got: %v", *rsrc, copy)
	}

	if fmt.Sprintf("%p", rsrc) == fmt.Sprintf("%p", &copy) {
		t.Errorf("pointers of original object and copy should not be same. object: %p, copy: %p", rsrc, &copy)
	}
}

func TestAddFieldSelector(t *testing.T) {
	tt := []struct {
		name          string
		initial       QueryableResource
		fieldSelector string
		expected      QueryableResource
	}{
		{
			name:          "Add to empty FieldSelectors",
			initial:       QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: ""},
			fieldSelector: "fs1",
			expected:      QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1"},
		},
		{
			name:          "Add to non-empty FieldSelectors",
			initial:       QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1"},
			fieldSelector: "fs2",
			expected:      QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1,fs2"},
		},
		{
			name:          "Add empty FieldSelector to non-empty FieldSelectors",
			initial:       QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1"},
			fieldSelector: "",
			expected:      QueryableResource{GroupVersionResourceTriplet: "gvr1", FieldSelectors: "fs1"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tc.initial.AddFieldSelector(tc.fieldSelector)

			if tc.initial != tc.expected {
				t.Errorf("Expected: %v, got: %v", tc.expected, tc.initial)
			}
		})
	}
}

func TestToK8sResourceMap(t *testing.T) {
	qrm := make(QueryableResources)
	qrm.Add(QueryableResource{GroupVersionResourceTriplet: "/v1/pods", FieldSelectors: "metadata.namespace=kube-system"})
	qrm.Add(QueryableResource{GroupVersionResourceTriplet: "/v1/pods", FieldSelectors: "metadata.namespace=default"})
	qrm.Add(QueryableResource{GroupVersionResourceTriplet: "/v1/nodes", FieldSelectors: ""})
	qrm.Add(QueryableResource{GroupVersionResourceTriplet: "batch/v1/jobs", FieldSelectors: ""})

	expectedResult := cautils.K8SResources{
		"/v1/pods":      nil,
		"/v1/nodes":     nil,
		"batch/v1/jobs": nil,
	}

	result := qrm.ToK8sResourceMap()

	if len(result) != len(expectedResult) {
		t.Fatalf("Expected: %v, got: %v", expectedResult, result)
	}

	for k, v := range result {
		if _, ok := expectedResult[k]; !ok || v != nil {
			t.Fatalf("Expected: %v, got: %v", expectedResult, result)
		}
	}
}

func TestAdd(t *testing.T) {
	qrMap := make(QueryableResources)
	qr := QueryableResource{GroupVersionResourceTriplet: "/v1/pods", FieldSelectors: "metadata.namespace=default"}
	qrMap.Add(qr)

	if resource, ok := qrMap["/v1/pods/metadata.namespace=default"]; !ok {
		t.Fatalf("Expected resource was not added to the map")
	} else if !reflect.DeepEqual(resource, qr) {
		t.Fatalf("Expected: %v, got: %v", qr, resource)
	}
}

package resourcehandler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

// TestPullSingleResource_LabelSelectorPassthrough verifies that a non-empty
// label selector is forwarded as-is to the Kubernetes LIST call, and that an
// empty selector leaves the label restriction unset.
func TestPullSingleResource_LabelSelectorPassthrough(t *testing.T) {
	tests := []struct {
		name                 string
		labelSelector        string
		wantLabelRestriction string
	}{
		{
			name:                 "empty label selector leaves restriction unset",
			labelSelector:        "",
			wantLabelRestriction: "",
		},
		{
			name:                 "equality-based selector is forwarded verbatim",
			labelSelector:        "app=nginx",
			wantLabelRestriction: "app=nginx",
		},
		{
			name:                 "inequality requirement is forwarded verbatim",
			labelSelector:        "env!=dev",
			wantLabelRestriction: "env!=dev",
		},
		{
			name:                 "multiple requirements comma-separated are forwarded verbatim",
			labelSelector:        "app=nginx,env=prod",
			wantLabelRestriction: "app=nginx,env=prod",
		},
		{
			name:                 "set-based in requirement is forwarded verbatim",
			labelSelector:        "env in (prod,staging)",
			wantLabelRestriction: "env in (prod,staging)",
		},
	}

	podList := &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedLabel string

			handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
				listAction, ok := action.(k8stesting.ListAction)
				require.True(t, ok)
				capturedLabel = listAction.GetListRestrictions().Labels.String()
				return true, podList, nil
			})

			gvr := &schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
			handler.pullSingleResource(context.Background(), gvr, tt.labelSelector, "", &EmptySelector{}, nil)

			assert.Equal(t, tt.wantLabelRestriction, capturedLabel,
				"label selector %q must reach listOptions.LabelSelector exactly", tt.labelSelector)
		})
	}
}

// TestPullResources_LabelSelectorPropagated verifies that a label selector
// passed to pullResources reaches every individual pullSingleResource LIST call.
func TestPullResources_LabelSelectorPropagated(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector string
	}{
		{
			name:          "no label selector leaves restriction unset",
			labelSelector: "",
		},
		{
			name:          "label selector reaches the API server call",
			labelSelector: "team=backend",
		},
	}

	podList := &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedLabels []string

			handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
				listAction, ok := action.(k8stesting.ListAction)
				if ok {
					capturedLabels = append(capturedLabels, listAction.GetListRestrictions().Labels.String())
				}
				return true, podList, nil
			})

			qrs := QueryableResources{
				"/v1/pods": QueryableResource{
					GroupVersionResourceTriplet: "/v1/pods",
					Namespaced:                  nil,
				},
			}

			handler.pullResources(context.Background(), qrs, &EmptySelector{}, tt.labelSelector)

			require.NotEmpty(t, capturedLabels,
				"pullResources must issue at least one LIST request")
			for _, got := range capturedLabels {
				assert.Equal(t, tt.labelSelector, got,
					"label selector must be forwarded to every LIST call")
			}
		})
	}
}

package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func bindingWithParamRef(paramRef map[string]any) unstructured.Unstructured {
	spec := map[string]any{"policyName": "kubescape-c-0012-policy"}
	if paramRef != nil {
		spec["paramRef"] = paramRef
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": "binding"},
		"spec":       spec,
	}}
}

func TestBindingsUseParamRef(t *testing.T) {
	tests := []struct {
		name     string
		bindings []unstructured.Unstructured
		want     bool
	}{
		{name: "no bindings", bindings: nil, want: false},
		{name: "binding without a paramRef", bindings: []unstructured.Unstructured{bindingWithParamRef(nil)}, want: false},
		{name: "paramRef naming an object", bindings: []unstructured.Unstructured{bindingWithParamRef(map[string]any{"name": "basic-control-configuration"})}, want: true},
		{
			name: "paramRef with only a selector",
			bindings: []unstructured.Unstructured{bindingWithParamRef(map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"tier": "strict"}},
			})},
			want: false,
		},
		{name: "binding with a nil object", bindings: []unstructured.Unstructured{{}}, want: false},
		{
			name: "one binding among several names a paramRef",
			bindings: []unstructured.Unstructured{
				bindingWithParamRef(nil),
				bindingWithParamRef(map[string]any{"name": "basic-control-configuration"}),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bindingsUseParamRef(tt.bindings))
		})
	}
}

var controlConfigGVR = schema.GroupVersionResource{Group: "kubescape.io", Version: "v1", Resource: "controlconfigurations"}

// vapCollectionHandler builds a handler whose fake cluster serves the VAP types
// and ControlConfigurations, and counts how often ControlConfigurations are listed.
func vapCollectionHandler(t *testing.T, bindings []unstructured.Unstructured, configListErr error) (*K8sResourceHandler, *int) {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}:       "ValidatingAdmissionPolicyList",
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}: "ValidatingAdmissionPolicyBindingList",
		controlConfigGVR: "ControlConfigurationList",
	}
	objs := []runtime.Object{&unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1",
		"kind":       "ControlConfiguration",
		"metadata":   map[string]any{"name": "basic-control-configuration"},
	}}}
	for i := range bindings {
		objs = append(objs, bindings[i].DeepCopy())
	}
	dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)
	lists := new(int)
	dyn.PrependReactor("list", "controlconfigurations", func(k8stesting.Action) (bool, runtime.Object, error) {
		*lists++
		if configListErr != nil {
			return true, nil, configListErr
		}
		return false, nil, nil
	})

	client := fakeclientset.NewClientset()
	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DynamicClient:    dyn,
		// No discovery client: vapreconcile then assumes the newest VAP version
		// instead of probing a fake that advertises nothing.
		Context: context.Background(),
	}
	return NewK8sResourceHandler(context.Background(), k8s, nil, nil, "test"), lists
}

func TestCollectVAPResourcesCollectsParamObjectsForParamRefBindings(t *testing.T) {
	handler, lists := vapCollectionHandler(t, []unstructured.Unstructured{
		bindingWithParamRef(map[string]any{"name": "basic-control-configuration"}),
	}, nil)
	session := &cautils.OPASessionObj{}

	handler.collectVAPResources(context.Background(), session)

	require.Len(t, session.VAPBindings, 1)
	assert.Equal(t, 1, *lists)
	require.Len(t, session.VAPParamObjects, 1)
	assert.Equal(t, "basic-control-configuration", session.VAPParamObjects[0].GetName())
}

func TestCollectVAPResourcesSkipsParamObjectsWithoutParamRefBindings(t *testing.T) {
	handler, lists := vapCollectionHandler(t, []unstructured.Unstructured{bindingWithParamRef(nil)}, nil)
	session := &cautils.OPASessionObj{}

	handler.collectVAPResources(context.Background(), session)

	require.Len(t, session.VAPBindings, 1)
	assert.Zero(t, *lists, "no binding names a paramRef, so ControlConfigurations must not be listed")
	assert.Empty(t, session.VAPParamObjects)
}

func TestCollectVAPResourcesKeepsBindingsWhenParamObjectsAreForbidden(t *testing.T) {
	forbidden := apierrors.NewForbidden(controlConfigGVR.GroupResource(), "", nil)
	handler, lists := vapCollectionHandler(t, []unstructured.Unstructured{
		bindingWithParamRef(map[string]any{"name": "basic-control-configuration"}),
	}, forbidden)
	session := &cautils.OPASessionObj{}

	handler.collectVAPResources(context.Background(), session)

	assert.Equal(t, 1, *lists)
	assert.Len(t, session.VAPBindings, 1, "a refused ControlConfiguration list must not drop the bindings")
	assert.Empty(t, session.VAPParamObjects)
}

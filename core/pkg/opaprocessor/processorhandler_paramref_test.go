package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// paramRefBindingFor builds a live binding for the control's policy carrying the
// given spec.paramRef.
func paramRefBindingFor(t *testing.T, controlID string, paramRef map[string]any) metav1unstructured.Unstructured {
	t.Helper()
	policyName, err := cel.PolicyNameForControl(controlID)
	require.NoError(t, err)
	return metav1unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": "binding"},
		"spec": map[string]any{
			"policyName": policyName,
			"paramRef":   paramRef,
		},
	}}
}

func paramRefProcessor(bindings ...metav1unstructured.Unstructured) *OPAProcessor {
	return &OPAProcessor{OPASessionObj: &cautils.OPASessionObj{VAPBindings: bindings}}
}

// TestRunCELOnK8sParamRef covers how a live binding hands the offline engine its
// params. A selector picks params the engine cannot resolve, and reading only
// the absent name left the policy on the bundled defaults instead. A name points
// at a cluster-scoped object, which the pod's own namespace never holds.
func TestRunCELOnK8sParamRef(t *testing.T) {
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "mutable", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "nginx"}},
		},
	}
	// privilegedPod adds a capability the bundled configuration calls insecure,
	// so only the binding's own params can clear it.
	privilegedPod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "privileged", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "c",
				"image": "nginx",
				"securityContext": map[string]any{
					"capabilities": map[string]any{"add": []any{"SETPCAP"}},
				},
			}},
		},
	}
	rule := &reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "cel-paramref"},
		RuleLanguage: reporthandling.CELLanguage,
	}

	t.Run("a params-bearing control refuses the whole rule", func(t *testing.T) {
		selector := map[string]any{"selector": map[string]any{
			"matchLabels": map[string]any{"tier": "strict"},
		}}
		opap := paramRefProcessor(paramRefBindingFor(t, "C-0046", selector))

		_, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod}, nil, "C-0046")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "spec.paramRef.selector")
	})

	t.Run("an empty selector still selects, so it is refused too", func(t *testing.T) {
		opap := paramRefProcessor(paramRefBindingFor(t, "C-0046", map[string]any{"selector": map[string]any{}}))

		_, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod}, nil, "C-0046")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "spec.paramRef.selector")
	})

	t.Run("a named paramRef resolves the cluster-scoped param object", func(t *testing.T) {
		// The bundled ControlConfiguration is scope: Cluster, so a named paramRef
		// carries no namespace and the object lives outside the pod's.
		config := objectsenvelopes.NewObject(map[string]any{
			"apiVersion": "kubescape.io/v1",
			"kind":       "ControlConfiguration",
			"metadata":   map[string]any{"name": "permissive-config"},
			"settings":   map[string]any{"insecureCapabilities": []any{}},
		})
		require.NotNil(t, config)

		opap := paramRefProcessor(paramRefBindingFor(t, "C-0046", map[string]any{"name": "permissive-config"}))
		opap.AllResources = map[string]workloadinterface.IMetadata{config.GetID(): config}

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{privilegedPod}, nil, "C-0046")
		require.NoError(t, err)
		assert.Empty(t, responses, "the binding's params allow every capability, so the pod passes")
	})

	t.Run("a paramless control ignores the selector, as the apiserver does", func(t *testing.T) {
		selector := map[string]any{"selector": map[string]any{
			"matchLabels": map[string]any{"tier": "strict"},
		}}
		opap := paramRefProcessor(paramRefBindingFor(t, "C-0017", selector))

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod}, nil, "C-0017")
		require.NoError(t, err)
		assert.Len(t, responses, 1, "C-0017 still flags the pod's mutable root filesystem")
	})
}

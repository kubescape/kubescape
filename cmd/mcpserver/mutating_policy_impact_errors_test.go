package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/mapreconcile"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

func TestClassifyScanError_MapReconcileForbidden(t *testing.T) {
	require.Equal(t, ErrCodeRBACDenied, classifyScanError(mapreconcile.ErrForbidden))
	wrapped := fmt.Errorf("%w: %s", mapreconcile.ErrForbidden, "mutatingadmissionpolicies")
	require.Equal(t, ErrCodeRBACDenied, classifyScanError(fmt.Errorf("collect: %w", wrapped)))
	require.Equal(t, ErrCodeScanFailed, classifyScanError(errors.New("not permitted")), "only the sentinel is reclassified")
}

func TestAnalyzeMutatingAdmissionPolicyImpact_FailuresAreClassified(t *testing.T) {
	denied := func(gvr schema.GroupVersionResource) error {
		return apierrors.NewForbidden(gvr.GroupResource(), "x", errors.New("denied"))
	}
	causes := []struct {
		name string
		err  func(schema.GroupVersionResource) error
		want ErrorCode
	}{
		{"forbidden", denied, ErrCodeRBACDenied},
		{"context canceled", func(schema.GroupVersionResource) error { return context.Canceled }, ErrCodeTimeout},
		{"deadline exceeded", func(schema.GroupVersionResource) error { return context.DeadlineExceeded }, ErrCodeTimeout},
		{"api server error", func(schema.GroupVersionResource) error { return apierrors.NewInternalError(errors.New("boom")) }, ErrCodeK8sClientError},
		{"generic error", func(schema.GroupVersionResource) error { return errors.New("connection refused") }, ErrCodeScanFailed},
	}
	paths := []struct {
		name     string
		verb     string
		resource string
		gvr      schema.GroupVersionResource
		// wantMessage is a fragment that must name the failing step.
		wantMessage string
	}{
		{"collect policies", "list", "mutatingadmissionpolicies", mutatingAdmissionPolicyGVR, "failed to collect MutatingAdmissionPolicy resources"},
		{"collect bindings", "list", "mutatingadmissionpolicybindings", mutatingAdmissionPolicyBindingGVR, "failed to collect MutatingAdmissionPolicy resources"},
		{"target resource", "get", "pods", testPodGVR, "failed to get resource prod/server"},
		{"namespace", "get", "namespaces", namespaceGVR, "failed to get namespace prod"},
	}

	for _, path := range paths {
		for _, cause := range causes {
			t.Run(path.name+"/"+cause.name, func(t *testing.T) {
				ksServer := newMutatingPolicyTestServer(t, unstructuredTestPod("prod", "server", nil))
				dyn := ksServer.k8sClient.DynamicClient.(interface {
					PrependReactor(verb, resource string, reaction k8stesting.ReactionFunc)
				})
				injected := cause.err(path.gvr)
				dyn.PrependReactor(path.verb, path.resource, func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, injected
				})

				result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
					"namespace":   "prod",
					"name":        "server",
					"api_version": "v1",
					"resource":    "pods",
				}))

				te := toolErrorOf(t, result)
				require.Equal(t, cause.want, te.Code)
				require.Contains(t, te.Message, path.wantMessage)
				if cause.name == "forbidden" && path.verb == "list" {
					// mapreconcile replaces the apiserver's Forbidden with its sentinel.
					require.Contains(t, te.Message, mapreconcile.ErrForbidden.Error())
					require.Contains(t, te.Message, path.gvr.Resource)
				} else {
					require.Contains(t, te.Message, injected.Error(), "message should keep the underlying error")
				}
			})
		}
	}
}

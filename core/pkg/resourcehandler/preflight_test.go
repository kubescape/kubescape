package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ssarReactor allows "list" access for every resource except those named in denied.
func ssarReactor(denied map[string]bool) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		ssar := createAction.GetObject().(*authorizationv1.SelfSubjectAccessReview)
		ssar.Status.Allowed = !denied[ssar.Spec.ResourceAttributes.Resource]
		if !ssar.Status.Allowed {
			ssar.Status.Reason = "forbidden"
		}
		return true, ssar, nil
	}
}

func TestPreflight_ReportsDeniedResourceWithAffectedControls(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", ssarReactor(map[string]bool{"clusterrolebindings": true}))

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	podControl := mockControl("C-0001", []reporthandling.PolicyRule{podRule})
	podControl.ControlID = "C-0001"
	crbRule := mockRule("crb-rule", []reporthandling.RuleMatchObjects{mockMatch(5)}, "")
	crbControl := mockControl("C-0002", []reporthandling.PolicyRule{crbRule})
	crbControl.ControlID = "C-0002"
	framework := mockFramework("test-framework", []reporthandling.Control{podControl, crbControl})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	denied := result.Denied()
	require.Len(t, denied, 1)
	assert.Contains(t, denied[0].GVR, "clusterrolebindings")
	assert.Contains(t, denied[0].AffectedControls, "C-0002")
}

func TestPreflight_AllAllowed(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", ssarReactor(nil))

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	podControl := mockControl("C-0001", []reporthandling.PolicyRule{podRule})
	framework := mockFramework("test-framework", []reporthandling.Control{podControl})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)
	assert.Empty(t, result.Denied())
	assert.NotEmpty(t, result.Checks)
}

func TestFileResourceHandler_PreflightNotSupported(t *testing.T) {
	handler := NewFileResourceHandler()
	_, err := handler.Preflight(context.Background(), &cautils.OPASessionObj{}, &cautils.ScanInfo{})
	assert.ErrorIs(t, err, ErrPreflightNotSupported)
}

package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ssarReactor allows "list" access for every resource except those named in
// denied. It also asserts that Preflight always asks for the cluster-wide
// "list" access the real collector needs, not a namespace-scoped one.
func ssarReactor(t *testing.T, denied map[string]bool) k8stesting.ReactionFunc {
	t.Helper()
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		ssar := createAction.GetObject().(*authorizationv1.SelfSubjectAccessReview)
		require.Equal(t, "list", ssar.Spec.ResourceAttributes.Verb)
		require.Empty(t, ssar.Spec.ResourceAttributes.Namespace)

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
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", ssarReactor(t, map[string]bool{"clusterrolebindings": true}))

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
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", ssarReactor(t, nil))

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

// TestPreflight_RequestFailureIsNotADenial guards against a failed
// SelfSubjectAccessReview request (timeout, API error, ...) being reported as
// the API server denying "list" - the two are not the same thing, and only
// the latter should count as a real denial.
func TestPreflight_RequestFailureIsNotADenial(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection reset")
	})

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	podControl := mockControl("C-0001", []reporthandling.PolicyRule{podRule})
	framework := mockFramework("test-framework", []reporthandling.Control{podControl})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.Empty(t, result.Denied(), "a failed request must not be reported as a denial")
	require.NotEmpty(t, result.Errored())
	for _, c := range result.Errored() {
		assert.Contains(t, c.Reason, "connection reset")
	}
}

func TestFileResourceHandler_PreflightNotSupported(t *testing.T) {
	handler := NewFileResourceHandler()
	_, err := handler.Preflight(context.Background(), &cautils.OPASessionObj{}, &cautils.ScanInfo{})
	assert.ErrorIs(t, err, ErrPreflightNotSupported)
}

// TestPreflight_SkipsExternalResources covers credentials scoped to the API
// groups a cluster actually serves: Kubescape's own resources must not turn
// into denials that fail the dry-run.
func TestPreflight_SkipsExternalResources(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})

	var reviewed []string
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, ssar.Spec.ResourceAttributes.Resource)
		// Stand in for credentials scoped to real API groups: anything outside
		// the core group is refused.
		ssar.Status.Allowed = ssar.Spec.ResourceAttributes.Group == ""
		return true, ssar, nil
	})

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"Pod"},
	}}, "")
	hostRule := mockRule("host-rule", []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"hostdata.kubescape.cloud"},
		APIVersions: []string{"v1beta0"},
		Resources:   []string{KubeletConfiguration, CNIInfo},
	}, {
		APIGroups:   []string{"armo.vuln.images"},
		APIVersions: []string{"v1"},
		Resources:   []string{ImageVulnerabilities},
	}, {
		APIGroups:   []string{"eks.amazonaws.com"},
		APIVersions: []string{"v1"},
		Resources:   []string{ClusterDescribe},
	}}, "")
	control := mockControl("C-0001", []reporthandling.PolicyRule{podRule, hostRule})
	framework := mockFramework("test-framework", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.Empty(t, result.Denied())
	assert.Equal(t, []string{"pods"}, reviewed)
	for _, check := range result.Checks {
		assert.NotContains(t, check.GVR, "hostdata.kubescape.cloud")
	}
}

// TestApplyAccessReviewStatus covers the access decisions a SubjectAccessReview
// can carry. Allowed=false with Denied=false is "no authorizer had an opinion",
// which is only a denial when they all reached one; an EvaluationError means a
// verdict was never reached and the check is unchecked rather than denied.
func TestApplyAccessReviewStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      authorizationv1.SubjectAccessReviewStatus
		wantAllowed bool
		wantErrored bool
		wantReason  string
	}{
		{
			name:        "allowed",
			status:      authorizationv1.SubjectAccessReviewStatus{Allowed: true, Reason: "RBAC: allowed by ClusterRole/view"},
			wantAllowed: true,
			wantReason:  "RBAC: allowed by ClusterRole/view",
		},
		{
			name:        "allowed despite a partial evaluation error",
			status:      authorizationv1.SubjectAccessReviewStatus{Allowed: true, EvaluationError: "role.rbac.authorization.k8s.io \"missing\" not found"},
			wantAllowed: true,
		},
		{
			name:       "no opinion with every authorizer reporting cleanly is a denial",
			status:     authorizationv1.SubjectAccessReviewStatus{},
			wantReason: "",
		},
		{
			name:       "explicit denial",
			status:     authorizationv1.SubjectAccessReviewStatus{Denied: true, Reason: "denied by webhook"},
			wantReason: "denied by webhook",
		},
		{
			name:       "explicit denial outranks an evaluation error",
			status:     authorizationv1.SubjectAccessReviewStatus{Denied: true, Reason: "denied by webhook", EvaluationError: "second authorizer timed out"},
			wantReason: "denied by webhook",
		},
		{
			name:        "no opinion with an evaluation error is unchecked",
			status:      authorizationv1.SubjectAccessReviewStatus{EvaluationError: "webhook: dial tcp 10.0.0.1:443 i/o timeout"},
			wantErrored: true,
			wantReason:  "webhook: dial tcp 10.0.0.1:443 i/o timeout",
		},
		{
			name:        "an evaluation error keeps the reason alongside it",
			status:      authorizationv1.SubjectAccessReviewStatus{Reason: "no RBAC policy matched", EvaluationError: "webhook timed out"},
			wantErrored: true,
			wantReason:  "no RBAC policy matched: webhook timed out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := GVRCheck{GVR: "agents.x-k8s.io/v1alpha1/sandboxes"}
			applyAccessReviewStatus(&check, tt.status)

			assert.Equal(t, tt.wantAllowed, check.Allowed)
			assert.Equal(t, tt.wantErrored, check.Errored)
			assert.Equal(t, tt.wantReason, check.Reason)

			result := &PreflightResult{Checks: []GVRCheck{check}}
			switch {
			case tt.wantAllowed:
				assert.Empty(t, result.Denied())
				assert.Empty(t, result.Errored())
			case tt.wantErrored:
				assert.Empty(t, result.Denied(), "an undecided check must not fail the dry-run")
				assert.Len(t, result.Errored(), 1)
			default:
				assert.Len(t, result.Denied(), 1)
				assert.Empty(t, result.Errored())
			}
		})
	}
}

// TestPreflight_UndecidedAccessReviewIsNotADenial covers a cluster whose webhook
// authorizer never answers: the API server returns no opinion plus an evaluation
// error, which must not fail the dry-run as missing RBAC.
func TestPreflight_UndecidedAccessReviewIsNotADenial(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		ssar.Status.EvaluationError = "webhook authorizer: dial tcp 10.0.0.1:443 i/o timeout"
		return true, ssar, nil
	})

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	podControl := mockControl("C-0001", []reporthandling.PolicyRule{podRule})
	framework := mockFramework("test-framework", []reporthandling.Control{podControl})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.Empty(t, result.Denied(), "an undecided access review must not be reported as a denial")
	require.NotEmpty(t, result.Errored())
	for _, c := range result.Errored() {
		assert.Contains(t, c.Reason, "i/o timeout")
	}
}

// TestPreflight_ExplicitDenialStillFailsTheDryRun guards the other direction:
// treating undecided reviews as unchecked must not soften a real denial.
func TestPreflight_ExplicitDenialStillFailsTheDryRun(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("preflight must not list resources: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	fakeClient := handler.k8s.KubernetesClient.(*fakeclientset.Clientset)
	fakeClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		ssar.Status.Denied = true
		ssar.Status.Reason = "denied by webhook"
		return true, ssar, nil
	})

	podRule := mockRule("pod-rule", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	podControl := mockControl("C-0001", []reporthandling.PolicyRule{podRule})
	framework := mockFramework("test-framework", []reporthandling.Control{podControl})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.Empty(t, result.Errored())
	require.NotEmpty(t, result.Denied())
	for _, c := range result.Denied() {
		assert.Equal(t, "denied by webhook", c.Reason)
	}
}

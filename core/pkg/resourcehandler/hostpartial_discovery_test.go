package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

const (
	// Virtual host identities: policy-Kind keys used by control
	// dependencies, the external map, infoMap, and conversion gaps alike —
	// even when discovery serves the transport CRDs under plural REST names.
	virtualHostKubeletGVR = "hostdata.kubescape.cloud/v1beta0/KubeletInfo"
	virtualHostProxyGVR   = "hostdata.kubescape.cloud/v1beta0/KubeProxyInfo"
)

// hostCRDResourceLists advertises the host-sensor CRDs the way a cluster
// with the node-agent installed reports them: lowercase plural resources
// served under the hostdata group.
func hostCRDResourceLists() []*metav1.APIResourceList {
	verbs := []string{"get", "list", "watch"}
	return []*metav1.APIResourceList{
		{
			GroupVersion: "hostdata.kubescape.cloud/v1beta0",
			APIResources: []metav1.APIResource{
				{Name: "kubeletinfos", Kind: "KubeletInfo", Namespaced: false, Verbs: verbs},
				{Name: "kubeproxyinfos", Kind: "KubeProxyInfo", Namespaced: false, Verbs: verbs},
			},
		},
	}
}

// newHandlerWithHostCRDs builds a handler whose discovery sees the host CRDs
// (like a cluster with the node-agent installed) and whose dynamic client
// lists nothing, so collection reaches the host-sensor stub.
func newHandlerWithHostCRDs(t *testing.T) *K8sResourceHandler {
	t.Helper()
	client := fakeclientset.NewClientset()
	client.Resources = hostCRDResourceLists()
	handler := getResourceHandlerMock()
	handler.k8s.KubernetesClient = client
	handler.k8s.DiscoveryClient = client.Discovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	return handler
}

// dynamicMatchControl builds a C-0069-shaped control: its host dependency
// arrives via DynamicMatch under the virtual Kind identity.
func dynamicMatchControl(controlID, resource string) reporthandling.Control {
	rule := mockRule(controlID+"-rule", nil, "")
	rule.DynamicMatch = []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"hostdata.kubescape.cloud"},
		APIVersions: []string{"v1beta0"},
		Resources:   []string{resource},
	}}
	control := mockControl(controlID, nil)
	control.ControlID = controlID
	control.Rules = []reporthandling.PolicyRule{rule}
	return control
}

// dynamicMatchFramework selects a KubeletInfo control and a KubeProxyInfo
// control, both through DynamicMatch.
func dynamicMatchFramework() *reporthandling.Framework {
	framework := mockFramework("host-dynamic-framework", nil)
	framework.Controls = []reporthandling.Control{
		dynamicMatchControl("C-0069", "KubeletInfo"),
		dynamicMatchControl("C-0070", "KubeProxyInfo"),
	}
	return framework
}

// virtualStubPartials are conversion gaps under the virtual Kind identity,
// as partialGVRPullsForResource emits them even with the host CRD installed.
func virtualStubPartials() []cautils.PartialGVRPull {
	return []cautils.PartialGVRPull{
		{GVR: virtualHostKubeletGVR, Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
		{GVR: virtualHostProxyGVR, Selector: "conversion", Error: "node-agent reported 2 KubeProxyInfo but only 1 could be read"},
	}
}

// TestGetResources_HostGapVirtualIdentityAcrossDiscovery is the HIGH
// regression under the virtual-identity scheme: with the host CRD installed
// (plural REST names on the wire), a relevant conversion gap still carries
// the Kind identity the DynamicMatch dependency uses, so it reaches coverage
// instead of being discarded as unrelated. Dropping it would let passing
// results escape IncompleteCoverage.
func TestGetResources_HostGapVirtualIdentityAcrossDiscovery(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := newHandlerWithHostCRDs(t)
	handler.hostSensorHandler = &stubHostSensor{partials: virtualStubPartials()}

	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *dynamicMatchFramework())

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	require.Contains(t, sessionObj.ResourceToControlsMap, virtualHostKubeletGVR,
		"precondition: DynamicMatch must store the virtual Kind identity")
	require.Len(t, sessionObj.PartialGVRFailures, 2,
		"both gaps carry the virtual identity backing effective selected controls")
	assert.Equal(t, virtualHostKubeletGVR, sessionObj.PartialGVRFailures[0].GVR)
	assert.Equal(t, virtualHostProxyGVR, sessionObj.PartialGVRFailures[1].GVR)
}

// TestGetResources_HostGapRespectsIncludeSkipControls is the MEDIUM
// regression on the eager path: the flags are real session fields (not
// pre-narrowed fixtures), and a gap required only by a filtered-out control
// must not penalize the scan.
func TestGetResources_HostGapRespectsIncludeSkipControls(t *testing.T) {
	tests := []struct {
		name       string
		skip       string
		include    string
		wantGVRs   []string
		wantAbsent []string
	}{
		{name: "skip proxy control", skip: "C-0070", wantGVRs: []string{virtualHostKubeletGVR}, wantAbsent: []string{virtualHostProxyGVR}},
		{name: "include kubelet control", include: "C-0069", wantGVRs: []string{virtualHostKubeletGVR}, wantAbsent: []string{virtualHostProxyGVR}},
		{name: "no flags keeps both", wantGVRs: []string{virtualHostKubeletGVR, virtualHostProxyGVR}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sinterface.InitializeMapResourcesMock()
			handler := newHandlerWithHostCRDs(t)
			handler.hostSensorHandler = &stubHostSensor{partials: virtualStubPartials()}

			scanInfo := &cautils.ScanInfo{SkipControls: tt.skip, IncludeControls: tt.include}
			scanInfo.HostSensorEnabled.SetBool(true)
			sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
			sessionObj.Policies = append(sessionObj.Policies, *dynamicMatchFramework())

			_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

			got := make([]string, 0, len(sessionObj.PartialGVRFailures))
			for _, p := range sessionObj.PartialGVRFailures {
				got = append(got, p.GVR)
			}
			assert.ElementsMatch(t, tt.wantGVRs, got)
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, got, absent)
			}
			if len(tt.wantGVRs) == 1 {
				coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
				require.Len(t, coverage.PartialGVRPulls, 1)
			}
		})
	}
}

// TestCollectAndStreamBatches_HostGapVirtualIdentity is the streaming-path
// mirror of the HIGH regression.
func TestCollectAndStreamBatches_HostGapVirtualIdentity(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithHostCRDs(t)
	handler.hostSensorHandler = &stubHostSensor{partials: virtualStubPartials()}
	scanInfo, session := streamingTestSession(ctx)
	session.Metadata.ScanMetadata.HostScanner = true
	framework := dynamicMatchFramework()
	session.Policies = append(session.Policies, *framework)
	session.ResourceToControlsMap = map[string][]string{
		virtualHostKubeletGVR: {framework.Controls[0].ControlID},
		virtualHostProxyGVR:   {framework.Controls[1].ControlID},
	}
	batches := make(chan *cautils.ResourceBatch, 1)

	err := handler.collectAndStreamBatches(
		ctx,
		QueryableResources{},
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{virtualHostKubeletGVR: nil, virtualHostProxyGVR: nil},
		batches,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, session.PartialGVRFailures, 2,
		"virtual-identity gaps backing effective selected controls must reach the session")
}

// TestCollectAndStreamBatches_HostGapRespectsIncludeSkipControls is the
// streaming-path mirror of the MEDIUM regression with real flag fields.
func TestCollectAndStreamBatches_HostGapRespectsIncludeSkipControls(t *testing.T) {
	tests := []struct {
		name     string
		skip     string
		include  string
		wantGVRs []string
	}{
		{name: "skip proxy control", skip: "C-0070", wantGVRs: []string{virtualHostKubeletGVR}},
		{name: "include kubelet control", include: "C-0069", wantGVRs: []string{virtualHostKubeletGVR}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler := newHandlerWithHostCRDs(t)
			handler.hostSensorHandler = &stubHostSensor{partials: virtualStubPartials()}
			scanInfo, session := streamingTestSession(ctx)
			session.Metadata.ScanMetadata.HostScanner = true
			framework := dynamicMatchFramework()
			session.Policies = append(session.Policies, *framework)
			session.SkipControls = tt.skip
			session.IncludeControls = tt.include
			session.ResourceToControlsMap = map[string][]string{
				virtualHostKubeletGVR: {framework.Controls[0].ControlID},
				virtualHostProxyGVR:   {framework.Controls[1].ControlID},
			}
			batches := make(chan *cautils.ResourceBatch, 1)

			err := handler.collectAndStreamBatches(
				ctx,
				QueryableResources{},
				&EmptySelector{},
				session,
				scanInfo,
				cautils.ExternalResources{virtualHostKubeletGVR: nil, virtualHostProxyGVR: nil},
				batches,
				nil,
			)

			require.NoError(t, err)
			got := make([]string, 0, len(session.PartialGVRFailures))
			for _, p := range session.PartialGVRFailures {
				got = append(got, p.GVR)
			}
			assert.ElementsMatch(t, tt.wantGVRs, got)
		})
	}
}

// TestEffectiveHostGapAllowlist_Unit pins the allowlist semantics directly:
// selected-control scoping, nil-session emptiness, and unfiltered fallback
// when the control filter errors.
func TestEffectiveHostGapAllowlist_Unit(t *testing.T) {
	framework := dynamicMatchFramework()
	policies := []reporthandling.Framework{*framework}

	newSession := func() *cautils.OPASessionObj {
		return &cautils.OPASessionObj{
			Policies: policies,
			ResourceToControlsMap: map[string][]string{
				virtualHostKubeletGVR: {framework.Controls[0].ControlID},
				virtualHostProxyGVR:   {framework.Controls[1].ControlID},
			},
		}
	}

	t.Run("no flags keeps all mapped gaps", func(t *testing.T) {
		allowed := effectiveHostGapAllowlist(newSession())
		assert.True(t, allowed[virtualHostKubeletGVR])
		assert.True(t, allowed[virtualHostProxyGVR])
		assert.False(t, allowed["other.example.com/v1/Things"])
	})

	t.Run("skip narrows to selected", func(t *testing.T) {
		session := newSession()
		session.SkipControls = "C-0070"
		allowed := effectiveHostGapAllowlist(session)
		assert.True(t, allowed[virtualHostKubeletGVR])
		assert.False(t, allowed[virtualHostProxyGVR])
	})

	t.Run("filter error falls back unfiltered", func(t *testing.T) {
		session := newSession()
		session.IncludeControls = "C-9999"
		allowed := effectiveHostGapAllowlist(session)
		assert.True(t, allowed[virtualHostKubeletGVR])
		assert.True(t, allowed[virtualHostProxyGVR])
	})

	t.Run("nil session is empty", func(t *testing.T) {
		assert.Empty(t, effectiveHostGapAllowlist(nil))
	})
}

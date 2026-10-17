package mcpserver

// Probe for the question "do the analyze_*/predict_* tools duplicate work or
// fan out unboundedly because they bypass doScanChan?".
//
// It measures, against a fake dynamic client that counts every LIST/GET and
// injects per-call latency:
//
//	direct   N identical concurrent tool calls, as the server dispatches them today
//	coalesced the same N calls routed through doScanChan (test-side wrapper only;
//	          no production code is changed) to show what coordination would do
//
// "direct" always means the production handler as registered. Against code
// that does not coalesce analysis requests it is the baseline (N x single-call);
// against code that does, it shows the effect of the production change. The
// counts are logged, not asserted, because overlap depends on scheduling;
// deterministic assertions live in analysis_coalescing_test.go.
//
// Discovery calls are counted separately: they go through a wrapper that
// sleeps outside the fake's internal lock, so peak in-flight covers them too.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	probeCallers = 32
	probeLatency = 10 * time.Millisecond
	probeWorkers = 25 // deployments with a vulnerability manifest, for the N+1 case
)

type apiCounter struct {
	lists, gets, discovery atomic.Int64
	inFlight, peak         atomic.Int64

	// latency is slept per request; zero for tests that synchronize
	// explicitly. hook, when set, runs for every request before it is
	// forwarded and may block or fail it.
	latency time.Duration
	hook    func(ctx context.Context) error
}

func (c *apiCounter) total() int64 {
	return c.lists.Load() + c.gets.Load() + c.discovery.Load()
}

// do accounts for one API request: it bumps the verb counter and tracks
// peak concurrency. Latency is injected by the wrappers below, outside the
// fake clientset's internal lock (which would otherwise serialize it).
func (c *apiCounter) do(ctx context.Context, counter *atomic.Int64) error {
	counter.Add(1)
	cur := c.inFlight.Add(1)
	for {
		p := c.peak.Load()
		if cur <= p || c.peak.CompareAndSwap(p, cur) {
			break
		}
	}
	defer c.inFlight.Add(-1)
	if c.hook != nil {
		if err := c.hook(ctx); err != nil {
			return err
		}
	}
	time.Sleep(c.latency)
	return nil
}

type countingDiscovery struct {
	discovery.DiscoveryInterface
	c *apiCounter
}

func (d countingDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	if err := d.c.do(context.Background(), &d.c.discovery); err != nil {
		return nil, err
	}
	return d.DiscoveryInterface.ServerResourcesForGroupVersion(gv)
}

type countingDynamic struct {
	dynamic.Interface
	c *apiCounter
}

func (d countingDynamic) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return countingResource{d.Interface.Resource(gvr), d.c}
}

type countingResource struct {
	dynamic.NamespaceableResourceInterface
	c *apiCounter
}

func (r countingResource) Namespace(ns string) dynamic.ResourceInterface {
	return countingNamespaced{r.NamespaceableResourceInterface.Namespace(ns), r.c}
}

func (r countingResource) List(ctx context.Context, o metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if err := r.c.do(ctx, &r.c.lists); err != nil {
		return nil, err
	}
	return r.NamespaceableResourceInterface.List(ctx, o)
}

func (r countingResource) Get(ctx context.Context, name string, o metav1.GetOptions, sub ...string) (*unstructured.Unstructured, error) {
	if err := r.c.do(ctx, &r.c.gets); err != nil {
		return nil, err
	}
	return r.NamespaceableResourceInterface.Get(ctx, name, o, sub...)
}

type countingNamespaced struct {
	dynamic.ResourceInterface
	c *apiCounter
}

func (r countingNamespaced) List(ctx context.Context, o metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if err := r.c.do(ctx, &r.c.lists); err != nil {
		return nil, err
	}
	return r.ResourceInterface.List(ctx, o)
}

func (r countingNamespaced) Get(ctx context.Context, name string, o metav1.GetOptions, sub ...string) (*unstructured.Unstructured, error) {
	if err := r.c.do(ctx, &r.c.gets); err != nil {
		return nil, err
	}
	return r.ResourceInterface.Get(ctx, name, o, sub...)
}

func (c *apiCounter) reset() {
	c.lists.Store(0)
	c.gets.Store(0)
	c.discovery.Store(0)
	c.inFlight.Store(0)
	c.peak.Store(0)
}

func newProbeServer(t *testing.T, counter *apiCounter) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		roleGVR: "RoleList", clusterRoleGVR: "ClusterRoleList",
		roleBindingGVR: "RoleBindingList", clusterRoleBindingGVR: "ClusterRoleBindingList",
		serviceAccountGVR: "ServiceAccountList",
		serviceGVR:        "ServiceList", ingressGVR: "IngressList", namespaceGVR: "NamespaceList",
		networkPolicyGVR: "NetworkPolicyList", podGVR: "PodList",
		httpRouteGVR: "HTTPRouteList", grpcRouteGVR: "GRPCRouteList", gatewayGVR: "GatewayList",
		httpRouteGVRv1beta1: "HTTPRouteList", grpcRouteGVRv1alpha2: "GRPCRouteList", gatewayGVRv1beta1: "GatewayList",
		referenceGrantGVR: "ReferenceGrantList", referenceGrantGVRv1beta1: "ReferenceGrantList",
		deploymentGVR: "DeploymentList", daemonSetGVR: "DaemonSetList", statefulSetGVR: "StatefulSetList",
		replicaSetGVR: "ReplicaSetList", jobGVR: "JobList", cronJobGVR: "CronJobList",
		mutatingAdmissionPolicyGVR:        "MutatingAdmissionPolicyList",
		mutatingAdmissionPolicyBindingGVR: "MutatingAdmissionPolicyBindingList",
	}

	objs := []runtime.Object{
		unstructuredServiceAccount("prod", "app"),
		unstructuredClusterRole("reader", unstructuredPolicyRule([]string{""}, []string{"pods"}, []string{"get"}, nil)),
		unstructuredClusterRoleBinding("crb", "reader", "prod", "app"),
		unstructuredTestPod("prod", "src", map[string]any{"app": "src"}),
		unstructuredTestPod("prod", "dst", map[string]any{"app": "dst"}),
		unstructuredMutatingPolicy("add-label", allPodsMatchConstraints()),
		unstructuredMutatingPolicyBinding("add-label-binding", "add-label"),
	}
	var manifests []runtime.Object
	for i := 0; i < probeWorkers; i++ {
		name := fmt.Sprintf("web-%d", i)
		objs = append(objs, unstructuredDeployment("prod", name, map[string]any{"app": name}))
		manifests = append(manifests, vulnerabilityManifest("prod", name+"-manifest",
			fmt.Sprintf("wlid://cluster-test/namespace-prod/deployment-%s", name), criticalMatch("CVE-2024-1")))
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)
	storage := storagefake.NewClientset(manifests...)

	fakeDiscovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	fakeDiscovery.Resources = []*metav1.APIResourceList{{
		GroupVersion: "admissionregistration.k8s.io/v1alpha1",
		APIResources: []metav1.APIResource{
			{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"},
			{Name: "mutatingadmissionpolicybindings", Kind: "MutatingAdmissionPolicyBinding"},
		},
	}}

	ksServer := &KubescapeMcpserver{
		s:         server.NewMCPServer("kubescape-test", "test", server.WithToolCapabilities(false), server.WithRecovery()),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: countingDynamic{dyn, counter}, DiscoveryClient: countingDiscovery{fakeDiscovery, counter}},
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			return storage.SpdxV1beta1(), nil
		},
	}
	createRBACEscalationTools(ksServer)
	createServiceExposureTools(ksServer)
	createPSSPredictorTools(ksServer)
	createVulnerabilityExposureTools(ksServer)
	createNetworkReachabilityTools(ksServer)
	createMutatingAdmissionPolicyTools(ksServer)
	return ksServer
}

// callTool dispatches one tools/call through the registered handler and returns
// the result text. Safe to call from non-test goroutines (no t.FailNow).
func callTool(ksServer *KubescapeMcpserver, tool string, args map[string]any) (string, error) {
	msg, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		return "", err
	}
	resp, ok := ksServer.s.HandleMessage(context.Background(), msg).(mcp.JSONRPCResponse)
	if !ok {
		return "", fmt.Errorf("protocol error from %s", tool)
	}
	var res *mcp.CallToolResult
	switch r := resp.Result.(type) {
	case *mcp.CallToolResult:
		res = r
	case mcp.CallToolResult:
		res = &r
	default:
		return "", fmt.Errorf("unexpected result type %T", resp.Result)
	}
	if res.IsError {
		return "", fmt.Errorf("%s returned a tool error: %v", tool, res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		return "", fmt.Errorf("non-text content from %s", tool)
	}
	return text.Text, nil
}

// fanOut runs callers identical calls released together and returns the
// responses. wrap, when non-nil, routes each call through doScanChan.
func fanOut(t *testing.T, ksServer *KubescapeMcpserver, tool string, args map[string]any, wrap func(func() (string, error)) (string, error)) []string {
	t.Helper()
	out := make([]string, probeCallers)
	errs := make([]error, probeCallers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < probeCallers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			call := func() (string, error) { return callTool(ksServer, tool, args) }
			if wrap != nil {
				out[i], errs[i] = wrap(call)
				return
			}
			out[i], errs[i] = call()
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
	}
	return out
}

func TestProbe_AnalysisToolsBypassScanCoordination(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"analyze_rbac_escalation_paths", map[string]any{"subject_kind": "ServiceAccount", "namespace": "prod", "name": "app"}},
		{"analyze_service_exposure", map[string]any{"namespace": "prod"}},
		{"predict_pss_compliance", map[string]any{"namespace": "prod"}},
		{"analyze_vulnerability_exposure", map[string]any{"namespace": "prod"}},
		{"analyze_network_reachability", map[string]any{
			"source_namespace": "prod", "source_pod": "src",
			"destination_namespace": "prod", "destination_pod": "dst",
		}},
		{"analyze_mutating_admission_policy_impact", map[string]any{
			"namespace": "prod", "name": "web-0", "api_group": "apps", "api_version": "v1", "resource": "deployments",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			counter := apiCounter{latency: probeLatency}
			ksServer := newProbeServer(t, &counter)

			// Baseline: API calls issued by exactly one invocation.
			single, err := callTool(ksServer, tc.tool, tc.args)
			require.NoError(t, err)
			perCall := counter.total()
			require.Positive(t, perCall)
			counter.reset()

			// Direct: how the server dispatches these tools today.
			began := time.Now()
			direct := fanOut(t, ksServer, tc.tool, tc.args, nil)
			directWall := time.Since(began)
			directCalls, directPeak := counter.total(), counter.peak.Load()
			counter.reset()

			// Coalesced: same handler body behind doScanChan, test-side only.
			key := "probe:" + tc.tool
			began = time.Now()
			coalesced := fanOut(t, ksServer, tc.tool, tc.args, func(call func() (string, error)) (string, error) {
				v, err := ksServer.doScanChan(context.Background(), key, func(context.Context) (interface{}, error) {
					return call()
				})
				if err != nil {
					return "", err
				}
				return v.(string), nil
			})
			coalescedWall := time.Since(began)
			coalescedCalls, coalescedPeak := counter.total(), counter.peak.Load()

			t.Logf("%-40s per-call=%3d API calls | direct: %4d calls, peak in-flight %2d, wall %v | via doScanChan: %3d calls, peak %d, wall %v",
				tc.tool, perCall, directCalls, directPeak, directWall.Round(time.Millisecond),
				coalescedCalls, coalescedPeak, coalescedWall.Round(time.Millisecond))

			// Correctness: every path returns the same answer as a lone call.
			for i := range direct {
				require.JSONEq(t, single, direct[i])
				require.JSONEq(t, single, coalesced[i])
			}

			// Overlap is scheduling-dependent, so counts are only sanity-checked
			// here; analysis_coalescing_test.go asserts coalescing deterministically.
			require.GreaterOrEqual(t, directCalls, perCall)
			require.GreaterOrEqual(t, coalescedCalls, perCall)
		})
	}
}

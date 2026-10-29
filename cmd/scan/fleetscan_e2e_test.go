package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPIServer is a minimal Kubernetes API server, with one namespace and one pod, that records every path it is asked for.
type fakeAPIServer struct {
	*httptest.Server
	delay        time.Duration
	unauthorized bool
	mu           sync.Mutex
	paths        []string
}

// newFakeAPIServer starts a fake cluster; delay slows every answer and unauthorized rejects every request.
func newFakeAPIServer(t *testing.T, delay time.Duration, unauthorized bool) *fakeAPIServer {
	t.Helper()
	server := &fakeAPIServer{delay: delay, unauthorized: unauthorized}
	server.Server = httptest.NewServer(http.HandlerFunc(server.serve))
	t.Cleanup(server.Close)
	return server
}

func (s *fakeAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-r.Context().Done():
			return
		}
	}
	if s.unauthorized {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Unauthorized", "code": 401})
		return
	}
	resources := map[string]struct {
		kind       string
		namespaced bool
		items      []map[string]any
	}{
		"namespaces":      {kind: "Namespace", items: []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "default", "uid": "ns-1"}}}},
		"pods":            {kind: "Pod", namespaced: true, items: []map[string]any{{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "web", "namespace": "default", "uid": "pod-1"}, "spec": map[string]any{"containers": []map[string]any{{"name": "web", "image": "nginx:1.27"}}}}}},
		"nodes":           {kind: "Node"},
		"serviceaccounts": {kind: "ServiceAccount", namespaced: true},
		"configmaps":      {kind: "ConfigMap", namespaced: true},
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch path {
	case "/version":
		writeJSON(w, http.StatusOK, map[string]any{"major": "1", "minor": "30", "gitVersion": "v1.30.0"})
		return
	case "/api":
		writeJSON(w, http.StatusOK, map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
		return
	case "/apis":
		writeJSON(w, http.StatusOK, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{}})
		return
	case "/api/v1":
		list := []map[string]any{}
		for name, resource := range resources {
			list = append(list, map[string]any{"name": name, "singularName": strings.TrimSuffix(name, "s"), "namespaced": resource.namespaced, "kind": resource.kind, "verbs": []string{"get", "list"}})
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": list})
		return
	}
	if resource, ok := resources[path[strings.LastIndex(path, "/")+1:]]; ok {
		items := resource.items
		if items == nil {
			items = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": resource.kind + "List", "apiVersion": "v1", "metadata": map[string]any{}, "items": items})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404})
}

// asked reports whether the server received a request for the path.
func (s *fakeAPIServer) asked(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.paths {
		if p == path {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// deadServerURL is the address of a server that has already stopped, so nothing answers there.
func deadServerURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	return url
}

// fleetRun is what one fleet scan produced.
type fleetRun struct {
	report   fleet.FleetReport
	summary  string
	exitCode int
	err      error
}

// runFleetE2E runs the real fleet scan, with local policies and no backend, against the given contexts and their API servers.
func runFleetE2E(t *testing.T, servers map[string]string, args ...string) fleetRun {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KUBECONFIG", writeE2EKubeconfig(t, dir, servers))
	t.Setenv("HOME", t.TempDir())
	noRetryWait(t)
	previousConfig, previousContext, previousConnected := k8sinterface.K8SConfig, k8sinterface.GetContextName(), k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() {
		k8sinterface.K8SConfig = previousConfig
		k8sinterface.SetClusterContextName(previousContext)
		k8sinterface.SetConnectedToCluster(previousConnected)
	})

	policies := filepath.Join("..", "..", "core", "cautils", "getter", "testdata")
	fleetReport := filepath.Join(dir, "fleet.json")
	args = append([]string{"framework", "nsa",
		"--output=" + filepath.Join(dir, "report.json"), "--format=json", "--fleet-report=" + fleetReport,
		"--keep-local", "--use-from=" + filepath.Join(policies, "NSA.json"),
		"--controls-config=" + filepath.Join(policies, "controls-inputs.json"), "--exceptions=" + filepath.Join(policies, "exceptions.json"),
	}, args...)

	var run fleetRun
	run.summary = captureStdout(t, func() {
		cmd := GetScanCommand(core.NewKubescape(context.Background()))
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs(args)
		run.err = cmd.Execute()
	})
	run.exitCode = shared.ExitCode(run.err)
	contents, err := os.ReadFile(fleetReport)
	require.NoError(t, err, "the fleet report is written whatever happened to the clusters")
	require.NoError(t, json.Unmarshal(contents, &run.report))
	return run
}

// writeE2EKubeconfig writes a kubeconfig with one context per server, each named after its context.
func writeE2EKubeconfig(t *testing.T, dir string, servers map[string]string) string {
	t.Helper()
	var clusters, contexts strings.Builder
	for name, url := range servers {
		fmt.Fprintf(&clusters, "- name: %s\n  cluster:\n    server: %s\n", name, url)
		fmt.Fprintf(&contexts, "- name: %s\n  context:\n    cluster: %s\n    user: user\n", name, name)
	}
	path := filepath.Join(dir, "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n" + clusters.String() + "contexts:\n" + contexts.String() + "users:\n- name: user\n  user:\n    token: e2e-token\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// clusterNamed returns the fleet report entry for the context.
func clusterNamed(t *testing.T, report fleet.FleetReport, name string) fleet.ClusterResult {
	t.Helper()
	for _, cluster := range report.Clusters {
		if cluster.ClusterID == name {
			return cluster
		}
	}
	require.Failf(t, "cluster missing from the fleet report", "%s", name)
	return fleet.ClusterResult{}
}

// TestFleetE2E_HealthyFleet pins that a fleet of reachable clusters is scanned, scored and exits 0.
func TestFleetE2E_HealthyFleet(t *testing.T) {
	servers := map[string]string{"prod": newFakeAPIServer(t, 0, false).URL, "staging": newFakeAPIServer(t, 0, false).URL}

	run := runFleetE2E(t, servers, "--kube-contexts=prod,staging")

	require.NoError(t, run.err)
	assert.Equal(t, 0, run.exitCode)
	for _, name := range []string{"prod", "staging"} {
		cluster := clusterNamed(t, run.report, name)
		assert.Equal(t, fleet.ClusterScanned, cluster.Status, name)
		assert.NotNil(t, cluster.ComplianceScore, name)
	}
	assert.Equal(t, 2, run.report.Compliance.ClustersScored)
	assert.Contains(t, run.summary, "(from 2 of 2 clusters)")
}

// TestFleetE2E_FailuresAreTold pins that a dead and a refusing cluster each get their own status, and the rest of the fleet is still scanned.
func TestFleetE2E_FailuresAreTold(t *testing.T) {
	servers := map[string]string{
		"prod":     newFakeAPIServer(t, 0, false).URL,
		"dead":     deadServerURL(t),
		"badcreds": newFakeAPIServer(t, 0, true).URL,
	}

	run := runFleetE2E(t, servers, "--kube-contexts=prod,dead,badcreds", "--retries=1")

	assert.Equal(t, 2, run.exitCode, "a cluster that could not be scanned makes the run incomplete")
	assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, "prod").Status)
	dead := clusterNamed(t, run.report, "dead")
	assert.Equal(t, fleet.ClusterUnreachable, dead.Status)
	assert.Equal(t, 2, dead.Attempts, "an unreachable cluster is retried")
	badcreds := clusterNamed(t, run.report, "badcreds")
	assert.Equal(t, fleet.ClusterError, badcreds.Status, "a cluster that answered is reachable, even if it refused")
	assert.Equal(t, 1, badcreds.Attempts, "a cluster that answered is not retried")
	assert.Equal(t, 1, run.report.Compliance.ClustersScored)
	for _, want := range []string{"unreachable (2 attempts)", "(from 1 of 3 clusters)", "dead was not counted", "badcreds was not counted"} {
		assert.Contains(t, run.summary, want)
	}
}

// TestFleetE2E_GateBreachExitsOne pins that a scanned fleet failing a threshold exits 1, not 2.
func TestFleetE2E_GateBreachExitsOne(t *testing.T) {
	servers := map[string]string{"prod": newFakeAPIServer(t, 0, false).URL}

	run := runFleetE2E(t, servers, "--kube-contexts=prod", "--compliance-threshold=100")

	require.ErrorContains(t, run.err, "below permitted threshold")
	assert.Equal(t, 1, run.exitCode)
	assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, "prod").Status, "a breach is still a measurement")
}

// TestFleetE2E_SlowClusterIsCancelledBeforeCollection pins that a cluster slower than --scan-timeout is cancelled before it is collected.
func TestFleetE2E_SlowClusterIsCancelledBeforeCollection(t *testing.T) {
	slow := newFakeAPIServer(t, 200*time.Millisecond, false)

	run := runFleetE2E(t, map[string]string{"slow": slow.URL}, "--kube-contexts=slow", "--retries=0", "--scan-timeout=300ms")

	assert.Equal(t, 2, run.exitCode)
	assert.Equal(t, fleet.ClusterCancelled, clusterNamed(t, run.report, "slow").Status)
	// Collection opens with /version and discovery, which take no context, so only the deadline check keeps them from being sent.
	assert.False(t, slow.asked("/version"), "a scan past its deadline must not start collecting")
	assert.False(t, slow.asked("/api/v1/pods"))
}

// TestFleetE2E_EveryClusterFailing pins that a fleet with nothing scanned still writes its report and summary, and exits 2.
func TestFleetE2E_EveryClusterFailing(t *testing.T) {
	servers := map[string]string{"dead-a": deadServerURL(t), "dead-b": deadServerURL(t)}

	run := runFleetE2E(t, servers, "--kube-contexts=dead-a,dead-b", "--retries=0")

	assert.Equal(t, 2, run.exitCode)
	for _, name := range []string{"dead-a", "dead-b"} {
		assert.Equal(t, fleet.ClusterUnreachable, clusterNamed(t, run.report, name).Status, name)
	}
	assert.Nil(t, run.report.Compliance.ComplianceScore, "no score when nothing was measured")
	assert.Contains(t, run.summary, "(from 0 of 2 clusters)")
}

// TestFleetE2E_FleetConfigFile pins that a real scan driven by a fleet config uses the file's contexts and retries.
func TestFleetE2E_FleetConfigFile(t *testing.T) {
	servers := map[string]string{"prod": newFakeAPIServer(t, 0, false).URL, "dead": deadServerURL(t)}
	config := filepath.Join(t.TempDir(), "fleet.yaml")
	require.NoError(t, os.WriteFile(config, []byte("apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts: [prod, dead]\n  retries: 0\n"), 0o600))

	run := runFleetE2E(t, servers, "--fleet-config="+config)

	assert.Equal(t, 2, run.exitCode)
	assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, "prod").Status)
	dead := clusterNamed(t, run.report, "dead")
	assert.Equal(t, fleet.ClusterUnreachable, dead.Status)
	assert.Equal(t, 1, dead.Attempts, "retries: 0 from the file means a single attempt")
}

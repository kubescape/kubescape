package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// fakeCluster stands in for the cluster getInterfaces connects to, recording every API call made against it.
func fakeCluster(t *testing.T) *fake.Clientset {
	t.Helper()
	clientset := fake.NewSimpleClientset()
	original := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		return &k8sinterface.KubernetesApi{KubernetesClient: clientset, DiscoveryClient: clientset.Discovery(), Context: context.Background()}
	}
	// A config must be set, or IsConnectedToCluster loads the machine's kubeconfig and the result depends on where the test runs.
	config, connected := k8sinterface.K8SConfig, k8sinterface.IsConnectedToCluster()
	k8sinterface.K8SConfig = &restclient.Config{Host: "https://fake-cluster.test"}
	k8sinterface.SetConnectedToCluster(true)
	t.Cleanup(func() {
		kubernetesAPIFunc = original
		k8sinterface.K8SConfig = config
		k8sinterface.SetConnectedToCluster(connected)
	})
	return clientset
}

// cancelOn cancels the scan the moment the cluster receives the given call.
func cancelOn(clientset *fake.Clientset, verb, resource string, cancel context.CancelFunc) {
	clientset.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return false, nil, nil
	})
}

// nodeLists counts the node lists the cluster received.
func nodeLists(clientset *fake.Clientset) int {
	count := 0
	for _, action := range clientset.Actions() {
		if action.Matches("list", "nodes") {
			count++
		}
	}
	return count
}

// TestGetInterfaces_StopsWhenTheDeadlineHasAlreadyPassed pins that an expired scan sends nothing after connecting.
func TestGetInterfaces_StopsWhenTheDeadlineHasAlreadyPassed(t *testing.T) {
	clientset := fakeCluster(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err := getInterfaces(ctx, &cautils.ScanInfo{}, nil)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.ErrorContains(t, err, "scan stopped while connecting to the cluster")
	assert.Empty(t, clientset.Actions(), "the version check takes no context, so it must not run once the deadline has passed")
}

// TestGetInterfaces_StopsWhenTheDeadlinePassesDuringTenantSetup pins that setup stops before the host sensor and cloud provider lookups.
func TestGetInterfaces_StopsWhenTheDeadlinePassesDuringTenantSetup(t *testing.T) {
	clientset := fakeCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The tenant config is read between the two checks; its last call is the secrets list.
	cancelOn(clientset, "list", "secrets", cancel)

	_, err := getInterfaces(ctx, &cautils.ScanInfo{Local: true}, nil)

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, nodeLists(clientset), "the cloud provider lookup must not run once the deadline has passed")
}

// TestScanContext_DoesNotCollectOnceTheDeadlineHasPassed pins that a deadline passing during setup stops the scan before discovery, dry run included.
func TestScanContext_DoesNotCollectOnceTheDeadlineHasPassed(t *testing.T) {
	for name, dryRun := range map[string]bool{"scan": false, "dry run": true} {
		t.Run(name, func(t *testing.T) {
			clientset := fakeCluster(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// With the version check off, the only node list is the cloud provider lookup at the end of setup.
			cancelOn(clientset, "list", "nodes", cancel)
			scanInfo, policyIdentifiers := localPolicyClusterScan(t)
			scanInfo.DryRun = dryRun

			_, err := NewKubescape(context.Background()).ScanContext(ctx, scanInfo, policyIdentifiers)

			require.ErrorIs(t, err, context.Canceled)
			assert.ErrorContains(t, err, "scan stopped before collecting resources")
			actions := clientset.Actions()
			require.NotEmpty(t, actions)
			assert.True(t, actions[len(actions)-1].Matches("list", "nodes"), "discovery takes no context, so it must not start: %v", actions[len(actions)-1])
		})
	}
}

// localPolicyClusterScan is a cluster scan whose policies all come from local files, so it needs no network.
func localPolicyClusterScan(t *testing.T) (*cautils.ScanInfo, []cautils.PolicyIdentifier) {
	t.Helper()
	dir := t.TempDir()
	rule := reporthandling.PolicyRule{Rule: "package armo_builtins\n\ndeny[msga] { false }"}
	rule.Name = "never-evaluated"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{{ControlID: "C-LOCAL", Rules: []reporthandling.PolicyRule{rule}}}}
	framework.Name = "local-framework"
	frameworkBytes, err := json.Marshal(framework)
	require.NoError(t, err)
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
		return path
	}
	scanInfo := &cautils.ScanInfo{
		UseFrom:        []string{write("framework.json", string(frameworkBytes))},
		ControlsInputs: write("controls-inputs.json", `{}`),
		UseExceptions:  write("exceptions.json", `[]`),
		AttackTracks:   write("attack-tracks.json", `[]`),
		Local:          true,
		FrameworkScan:  true,
		ScanType:       cautils.ScanTypeFramework,
	}
	scanInfo.Submit.SetBool(false)
	return scanInfo, []cautils.PolicyIdentifier{{Identifier: framework.Name, Kind: apisv1.KindFramework}}
}

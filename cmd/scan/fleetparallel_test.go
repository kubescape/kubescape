package scan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fleetChildEnv = "KUBESCAPE_TEST_FLEET_CHILD"

// TestMain lets the test binary stand in for kubescape when a parallel fleet scan starts a child.
func TestMain(m *testing.M) {
	if os.Getenv(fleetChildEnv) == "1" {
		cmd := GetScanCommand(core.NewKubescape(context.Background()))
		cmd.SetArgs(os.Args[1:])
		os.Exit(shared.ExitCode(cmd.Execute()))
	}
	os.Exit(m.Run())
}

// useTestBinaryForChildren makes child scans run this test binary as kubescape, and counts them.
func useTestBinaryForChildren(t *testing.T) *atomic.Int32 {
	t.Helper()
	previous := fleetChildCommand
	t.Cleanup(func() { fleetChildCommand = previous })
	started := &atomic.Int32{}
	fleetChildCommand = func(ctx context.Context, args []string) (*exec.Cmd, error) {
		started.Add(1)
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		command := exec.CommandContext(ctx, executable, args...)
		command.Env = append(os.Environ(), fleetChildEnv+"=1")
		return command, nil
	}
	return started
}

// podsInReport counts the pods a per-context report holds.
func podsInReport(t *testing.T, path string) int {
	t.Helper()
	contents, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G703: the test reads a report it just wrote to its own temp dir
	require.NoError(t, err)
	var report struct {
		Resources []struct {
			Object map[string]any `json:"object"`
		} `json:"resources"`
	}
	require.NoError(t, json.Unmarshal(contents, &report))
	pods := 0
	for _, resource := range report.Resources {
		if resource.Object["kind"] == "Pod" {
			pods++
		}
	}
	return pods
}

// TestFleetE2E_ParallelKeepsEachClusterApart pins that clusters scanned at once each get their own data.
func TestFleetE2E_ParallelKeepsEachClusterApart(t *testing.T) {
	started := useTestBinaryForChildren(t)
	servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL, "beta": newFakeAPIServerWithPods(t, 11).URL}

	run := runFleetE2E(t, servers, "--kube-contexts=alpha,beta", "--parallel=2", "--retries=0")

	require.NoError(t, run.err)
	assert.Equal(t, int32(2), started.Load(), "each context is scanned in its own process")
	dir := filepath.Dir(filepath.Join(os.Getenv("KUBECONFIG")))
	assert.Equal(t, 3, podsInReport(t, filepath.Join(dir, "report.alpha.json")))
	assert.Equal(t, 11, podsInReport(t, filepath.Join(dir, "report.beta.json")))
	for _, name := range []string{"alpha", "beta"} {
		cluster := clusterNamed(t, run.report, name)
		assert.Equal(t, fleet.ClusterScanned, cluster.Status)
		assert.NotNil(t, cluster.Report, "the child's report is carried into the fleet report")
	}
	assert.Equal(t, 2, run.report.Compliance.ClustersScored)
}

// TestFleetE2E_ParallelMatchesSequential pins that scanning in child processes gives the same fleet report.
func TestFleetE2E_ParallelMatchesSequential(t *testing.T) {
	started := useTestBinaryForChildren(t)
	servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL, "beta": newFakeAPIServerWithPods(t, 11).URL}

	sequential := runFleetE2E(t, servers, "--kube-contexts=alpha,beta", "--retries=0")
	parallel := runFleetE2E(t, servers, "--kube-contexts=alpha,beta", "--retries=0", "--parallel=2")

	require.NoError(t, sequential.err)
	require.NoError(t, parallel.err)
	assert.Equal(t, int32(2), started.Load(), "only the --parallel run starts processes")
	assert.Equal(t, sequential.report.Compliance, parallel.report.Compliance)
	assert.Equal(t, sequential.report.ControlMatrix, parallel.report.ControlMatrix)
	assert.Equal(t, sequential.report.Divergence, parallel.report.Divergence)
}

// TestFleetE2E_ParallelKeepsExitCodes pins the statuses and exit codes when children fail.
func TestFleetE2E_ParallelKeepsExitCodes(t *testing.T) {
	useTestBinaryForChildren(t)

	t.Run("unreachable cluster", func(t *testing.T) {
		servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL, "dead": deadServerURL(t)}
		run := runFleetE2E(t, servers, "--kube-contexts=alpha,dead", "--parallel=2", "--retries=0")
		assert.Equal(t, exitIncomplete, run.exitCode)
		assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, "alpha").Status)
		assert.Equal(t, fleet.ClusterUnreachable, clusterNamed(t, run.report, "dead").Status)
		assert.Contains(t, run.err.Error(), "dead: ")
	})

	t.Run("failed gate", func(t *testing.T) {
		servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL, "beta": newFakeAPIServerWithPods(t, 11).URL}
		run := runFleetE2E(t, servers, "--kube-contexts=alpha,beta", "--parallel=2", "--retries=0", "--compliance-threshold=100")
		assert.Equal(t, exitGateFailed, run.exitCode)
		assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, "beta").Status)
	})
}

// TestValidateParallel pins the --parallel values that are rejected.
func TestValidateParallel(t *testing.T) {
	servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL}
	tests := map[string]struct {
		args []string
		want string
	}{
		"zero":             {args: []string{"--kube-contexts=alpha", "--parallel=0"}, want: "--parallel 0 must be at least 1"},
		"without contexts": {args: []string{"--parallel=2", "--fleet-report="}, want: "--parallel requires --kube-contexts"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			run := scanFleetE2E(t, prepareFleetE2E(t, servers), tt.args...)
			require.Error(t, run.err)
			assert.Contains(t, run.err.Error(), tt.want)
		})
	}
}

// TestFleetChildArgs pins how the user's command is repeated for one context.
func TestFleetChildArgs(t *testing.T) {
	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	var invocation fleetCommandLine
	for _, sub := range cmd.Commands() {
		if sub.Name() == "framework" {
			invocation.cmd = sub
		}
	}
	require.NotNil(t, invocation.cmd)
	require.NoError(t, invocation.cmd.ParseFlags([]string{
		"--kube-contexts=prod,staging", "--fleet-report=fleet.json", "--retries=3", "--parallel=2", "--output=report.json",
		"--format=json", "--exclude-namespaces=kube-system,kube-public", "--exclude-controls=C-0001,C-0002",
		"--notify=https://a.example", "--notify=https://b.example", "--registry-mapping=a.io=b.io,c.io=d.io",
		"--submit=false", "--compliance-threshold=80",
	}))
	invocation.args = []string{"nsa"}

	args := fleetChildArgs(fleetChildBaseArgs(invocation), invocation.args, "prod", "report.json", "/tmp/0.json", 3)

	assert.Equal(t, "framework", args[0])
	assert.Subset(t, args, []string{
		"--format=json", "--exclude-namespaces=kube-system,kube-public", "--exclude-controls=C-0001", "--exclude-controls=C-0002",
		"--notify=https://a.example", "--notify=https://b.example",
		"--registry-mapping=a.io=b.io", "--registry-mapping=c.io=d.io", "--submit=false", "--compliance-threshold=80",
		"--kube-contexts=prod", "--output=report.json", "--fleet-report=/tmp/0.json", "--retries=3",
	})
	assert.NotContains(t, args, "--parallel=2", "the child scans one context, so it never starts children of its own")
	assert.NotContains(t, args, "--kube-contexts=prod,staging")
	assert.Equal(t, []string{"--", "nsa"}, args[len(args)-2:])
}

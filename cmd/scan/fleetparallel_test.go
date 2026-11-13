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
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/spf13/pflag"
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

// TestFleetE2E_ParallelKeepsPrivacyModes pins that --hide and --encrypt work with --parallel when no fleet report is asked for.
func TestFleetE2E_ParallelKeepsPrivacyModes(t *testing.T) {
	for _, mode := range []string{"--hide", "--encrypt"} {
		t.Run(mode, func(t *testing.T) {
			started := useTestBinaryForChildren(t)
			t.Setenv("KUBESCAPE_MASTER_KEY", "0123456789abcdef0123456789abcdef")
			t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")
			servers := map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL, "beta": newFakeAPIServerWithPods(t, 11).URL}
			fleetReport := prepareFleetE2E(t, servers)

			run := scanFleetE2E(t, fleetReport, "--kube-contexts=alpha,beta", "--parallel=2", "--retries=0", "--fleet-report=", mode)

			require.NoError(t, run.err)
			assert.Equal(t, int32(2), started.Load())
			for _, name := range []string{"alpha", "beta"} {
				assert.FileExists(t, filepath.Join(filepath.Dir(fleetReport), "report."+name+".json"))
			}
			assert.NoFileExists(t, fleetReport)
		})
	}
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

// frameworkInvocation is "scan framework nsa" parsed with the given flags, as the user would have run it.
func frameworkInvocation(t *testing.T, flags ...string) fleetCommandLine {
	t.Helper()
	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	invocation := fleetCommandLine{args: []string{"nsa"}}
	for _, sub := range cmd.Commands() {
		if sub.Name() == "framework" {
			invocation.cmd = sub
		}
	}
	require.NotNil(t, invocation.cmd)
	require.NoError(t, invocation.cmd.ParseFlags(flags))
	return invocation
}

// TestFleetChildArgs pins how the user's command is repeated for one context.
func TestFleetChildArgs(t *testing.T) {
	invocation := frameworkInvocation(t,
		"--kube-contexts=prod,staging", "--fleet-report=fleet.json", "--retries=3", "--parallel=2", "--output=report.json",
		"--format=json", "--exclude-namespaces=kube-system,kube-public", "--exclude-controls=C-0001,C-0002",
		"--notify=https://a.example", "--notify=https://b.example", "--registry-mapping=a.io=b.io,c.io=d.io",
		"--submit=false", "--compliance-threshold=80",
	)

	args := fleetChildArgs(fleetChildBaseArgs(invocation), invocation.args, "prod", "report.json", "/tmp/0.json", 3)

	assert.Equal(t, "framework", args[0])
	assert.Subset(t, args, []string{
		"--format=json", "--exclude-namespaces=kube-system,kube-public", "--exclude-controls=C-0001", "--exclude-controls=C-0002",
		"--notify=https://a.example", "--notify=https://b.example",
		"--registry-mapping=a.io=b.io", "--registry-mapping=c.io=d.io", "--submit=false", "--compliance-threshold=80",
		"--kube-contexts=prod", "--output=report.json", "--fleet-child-result=/tmp/0.json", "--retries=3",
	})
	assert.NotContains(t, args, "--parallel=2", "the child scans one context, so it never starts children of its own")
	assert.NotContains(t, args, "--kube-contexts=prod,staging")
	assert.NotContains(t, args, "--fleet-report=fleet.json", "the child's result is internal, so the user's fleet report checks do not apply to it")
	assert.Equal(t, []string{"--", "nsa"}, args[len(args)-2:])
}

// TestFleetChildArgsRoundTrip pins that the child parses back the same values the user gave, commas and quotes included.
func TestFleetChildArgsRoundTrip(t *testing.T) {
	invocation := frameworkInvocation(t,
		`--use-from="policies/team,a.json",b.json`, `--values="charts/a,b.yaml"`, `--api-versions=""`,
		"--exclude-path=a,b", `--exclude-path=say "hi"`,
		"--registry-mapping=a.io=b,c", `--registry-mapping="k=a=b,c"`, `--registry-mapping=q.io=x"y`,
	)

	args := fleetChildArgs(fleetChildBaseArgs(invocation), invocation.args, "prod,eu", "report.json", "/tmp/0.json", 0)
	child := frameworkInvocation(t, args[1:len(args)-2]...)

	parent, parsed := invocation.cmd.Flags(), child.cmd.Flags()
	// GetSlice, since GetStringSlice reads an empty value back as no value.
	values := func(flags *pflag.FlagSet, name string) []string {
		return flags.Lookup(name).Value.(pflag.SliceValue).GetSlice()
	}
	assert.Equal(t, []string{"policies/team,a.json", "b.json"}, values(parent, "use-from"))
	assert.Equal(t, []string{"charts/a,b.yaml"}, values(parent, "values"))
	assert.Equal(t, []string{""}, values(parent, "api-versions"))
	assert.Equal(t, []string{"a,b", `say "hi"`}, values(parent, "exclude-path"))
	for _, name := range []string{"use-from", "values", "api-versions", "exclude-path"} {
		assert.Equal(t, values(parent, name), values(parsed, name), name)
	}
	assert.Equal(t, []string{"prod,eu"}, values(parsed, "kube-contexts"))
	wantMap, _ := parent.GetStringToString("registry-mapping")
	gotMap, _ := parsed.GetStringToString("registry-mapping")
	assert.Equal(t, map[string]string{"a.io": "b,c", "k": "a=b,c", "q.io": `x"y`}, wantMap)
	assert.Equal(t, wantMap, gotMap)
}

// TestFleetParallelKeepsReportsOnlyForFleetReport pins that the parent holds each child's report only when a fleet report reads it.
func TestFleetParallelKeepsReportsOnlyForFleetReport(t *testing.T) {
	useTestBinaryForChildren(t)
	fleetReport := prepareFleetE2E(t, map[string]string{"alpha": newFakeAPIServerWithPods(t, 3).URL})
	policies := filepath.Join("..", "..", "core", "cautils", "getter", "testdata")
	previous := fleetInvocation
	t.Cleanup(func() { fleetInvocation = previous })
	fleetInvocation = frameworkInvocation(t, "--format=json", "--keep-local", "--use-from="+filepath.Join(policies, "NSA.json"),
		"--controls-config="+filepath.Join(policies, "controls-inputs.json"), "--exceptions="+filepath.Join(policies, "exceptions.json"))

	for name, report := range map[string]string{"without a fleet report": "", "with a fleet report": fleetReport} {
		t.Run(name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{KubeContexts: []string{"alpha"}, KubeContextParallel: 2, Output: filepath.Join(filepath.Dir(fleetReport), "report.json"), FleetReport: report}
			outcomes := scanFleetInProcesses(context.Background(), scanInfo, nil)
			require.Len(t, outcomes, 1)
			require.NoError(t, outcomes[0].err)
			assert.True(t, outcomes[0].scanned, "the status is kept either way")
			assert.Equal(t, report != "", outcomes[0].cluster.Report != nil)
		})
	}
}

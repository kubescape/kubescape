package fixhandler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestResource(kind, name, namespace string) *reporthandling.Resource {
	return &reporthandling.Resource{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       kind,
			"metadata": map[string]any{
				"name":      name,
				"namespace": namespace,
			},
		},
	}
}

func TestPrintExpectedChanges_Color_FilePathIsWhite(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	res := newTestResource("Deployment", "api-server", "prod")
	toFix := []ResourceFixInfo{
		{
			Resource:      res,
			FilePath:      "/manifests/deploy.yaml",
			DocumentIndex: 0,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {Path: "spec.replicas", Value: "3"},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, true)

	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("File:"))
	assert.Contains(t, out, gchalk.BrightWhite("/manifests/deploy.yaml"))
	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("Namespace:"))
	assert.Contains(t, out, gchalk.BrightWhite("prod"))
	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("Document index:"))
	assert.Contains(t, out, gchalk.BrightWhite("0"))
}

func TestPrintExpectedChanges_Color_ResourceIsCyan(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	res := newTestResource("StatefulSet", "db", "")
	toFix := []ResourceFixInfo{
		{
			Resource: res,
			FilePath: "db.yaml",
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.serviceName": {Path: "spec.serviceName", Value: "db-svc"},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, true)

	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("Resource:"))
	assert.Contains(t, out, gchalk.BrightWhite("db"))
	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("Kind:"))
	assert.Contains(t, out, gchalk.BrightWhite("StatefulSet"))
	assert.Contains(t, out, gchalk.Bold("Changes:"))
}

func TestPrintExpectedChanges_Color_PatchPathIsYellow(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	res := newTestResource("Pod", "test-pod", "default")
	toFix := []ResourceFixInfo{
		{
			Resource: res,
			FilePath: "pod.yaml",
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.containers[0].securityContext.allowPrivilegeEscalation": {
					Path:  "spec.containers[0].securityContext.allowPrivilegeEscalation",
					Value: "false",
				},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, true)

	assert.Contains(t, out, gchalk.BrightYellow("spec.containers[0].securityContext.allowPrivilegeEscalation"))
}

func TestPrintExpectedChanges_Color_PatchValueIsGreen(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	res := newTestResource("Pod", "test-pod", "default")
	toFix := []ResourceFixInfo{
		{
			Resource: res,
			FilePath: "pod.yaml",
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.containers[0].image": {
					Path:  "spec.containers[0].image",
					Value: "nginx:1.25-alpine",
				},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, true)

	assert.Contains(t, out, gchalk.BrightGreen("nginx:1.25-alpine"))
}

func TestPrintExpectedChanges_Color_ClusterSource(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	resWithNs := newTestResource("DaemonSet", "fluentd", "kube-system")
	resNoNs := newTestResource("ClusterRole", "view", "")

	toFix := []ResourceFixInfo{
		{
			Resource: resWithNs,
			inMemory: true,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.minReadySeconds": {Path: "spec.minReadySeconds", Value: "10"},
			},
		},
		{
			Resource: resNoNs,
			inMemory: true,
			YamlExpressions: map[string]armotypes.FixPath{
				"rules[0].verbs": {Path: "rules[0].verbs", Value: "get"},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, true)

	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("Source:"))
	assert.Contains(t, out, gchalk.BrightWhite("cluster, namespace kube-system"))
	assert.Contains(t, out, gchalk.BrightWhite("cluster"))
}

func TestPrintExpectedChanges_NoColor(t *testing.T) {
	res := newTestResource("Deployment", "api-server", "prod")
	toFix := []ResourceFixInfo{
		{
			Resource:      res,
			FilePath:      "/manifests/deploy.yaml",
			DocumentIndex: 1,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {Path: "spec.replicas", Value: "3"},
			},
		},
	}

	out := formatExpectedChangesWithColor(toFix, false)

	assert.NotContains(t, out, "\x1b[", "Uncolored output must contain zero ANSI escape codes")
	assert.Contains(t, out, "File: /manifests/deploy.yaml\n")
	assert.Contains(t, out, "Namespace: prod\n")
	assert.Contains(t, out, "Document index: 1\n")
	assert.Contains(t, out, "Resource: api-server\n")
	assert.Contains(t, out, "Kind: Deployment\n")
	assert.Contains(t, out, "Changes:\n")
	assert.Contains(t, out, "\t1) spec.replicas = 3\n")
}

func TestPrintUnfixedControls_Color_ControlIDIsCyan(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	h := &FixHandler{
		fixedControlsCount: 2,
		unfixedControls: []UnfixedControl{
			{
				ControlID:    "C-0012",
				ControlName:  "HostNetwork",
				ResourceKind: "Deployment",
				ResourceName: "nginx",
				FilePath:     "deploy.yaml",
				Reason:       "requires host network configuration review",
			},
		},
	}

	out := h.formatUnfixedControlsWithColor(PhasePlanned, true)

	assert.Contains(t, out, gchalk.WithBrightCyan().Bold("C-0012"))
	assert.Contains(t, out, "HostNetwork on Deployment/nginx")
}

func TestPrintUnfixedControls_Color_LocationIsYellow(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	h := &FixHandler{
		fixedControlsCount: 0,
		unfixedControls: []UnfixedControl{
			{
				ControlID:    "C-0057",
				ControlName:  "PrivilegedContainer",
				ResourceKind: "Pod",
				ResourceName: "app",
				FilePath:     "/var/manifests/app.yaml",
				Reason:       "manual review required",
			},
			{
				ControlID:    "C-0058",
				ControlName:  "AllowPrivilegeEscalation",
				ResourceKind: "Pod",
				ResourceName: "app",
				FilePath:     "",
				Reason:       "live cluster object has no manifest",
			},
		},
	}

	out := h.formatUnfixedControlsWithColor(PhaseApplied, true)

	assert.Contains(t, out, gchalk.Yellow("/var/manifests/app.yaml"))
	assert.Contains(t, out, gchalk.Yellow("<unknown>"))
}

func TestPrintUnfixedControls_Color_ReasonIsRed(t *testing.T) {
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	h := &FixHandler{
		fixedControlsCount: 1,
		unfixedControls: []UnfixedControl{
			{
				ControlID:    "C-0038",
				ControlName:  "HostPID",
				ResourceKind: "DaemonSet",
				ResourceName: "agent",
				FilePath:     "daemonset.yaml",
				Reason:       "cannot safely mutate hostPID without operator confirmation",
			},
		},
	}

	out := h.formatUnfixedControlsWithColor(PhasePlanned, true)

	assert.Contains(t, out, gchalk.Red("cannot safely mutate hostPID without operator confirmation"))
}

func TestPrintUnfixedControls_NoColor(t *testing.T) {
	h := &FixHandler{
		fixedControlsCount: 3,
		unfixedControls: []UnfixedControl{
			{
				ControlID:    "C-0041",
				ControlName:  "HostPort",
				ResourceKind: "Deployment",
				ResourceName: "web",
				FilePath:     "web.yaml",
				Reason:       "cannot auto-fix hostPort",
			},
		},
	}

	out := h.formatUnfixedControlsWithColor(PhaseApplied, false)

	assert.NotContains(t, out, "\x1b[", "Uncolored unfixed controls output must contain zero ANSI escape codes")
	assert.Contains(t, out, "Auto-fixed 3 of 4 flagged control instances.")
	assert.Contains(t, out, "  - C-0041 HostPort on Deployment/web (web.yaml) — cannot auto-fix hostPort\n")
}

func TestPrintUnfixedControls_Color_EmptyReturnsEmpty(t *testing.T) {
	h := &FixHandler{
		unfixedControls: nil,
	}

	out := h.formatUnfixedControlsWithColor(PhasePlanned, true)
	assert.Empty(t, out)

	// Call PrintUnfixedControls directly to ensure no panic
	h.PrintUnfixedControls(PhasePlanned)
}

func TestShouldColor_EnvPrecedence(t *testing.T) {
	// NO_COLOR non-empty forces false even if FORCE_COLOR=1
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "1")
	assert.False(t, shouldColor(), "NO_COLOR must take precedence over FORCE_COLOR")

	// NO_COLOR empty string should be treated as unset, allowing FORCE_COLOR=1
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	assert.True(t, shouldColor(), "FORCE_COLOR=1 must enable color when NO_COLOR is empty")

	// FORCE_COLOR=0 disables color
	os.Unsetenv("NO_COLOR")
	t.Setenv("FORCE_COLOR", "0")
	assert.False(t, shouldColor(), "FORCE_COLOR=0 must disable color")

	// FORCE_COLOR=-1 enables color (nonzero integer forces color per #4518)
	t.Setenv("FORCE_COLOR", "-1")
	assert.True(t, shouldColor(), "FORCE_COLOR=-1 must enable color")

	// FORCE_COLOR=false disables color
	t.Setenv("FORCE_COLOR", "false")
	assert.False(t, shouldColor(), "FORCE_COLOR=false must disable color")

	// FORCE_COLOR=true enables color
	t.Setenv("FORCE_COLOR", "true")
	assert.True(t, shouldColor(), "FORCE_COLOR=true must enable color")

	// FORCE_COLOR=2 and FORCE_COLOR=3 enable color
	t.Setenv("FORCE_COLOR", "2")
	assert.True(t, shouldColor(), "FORCE_COLOR=2 must enable color")
	t.Setenv("FORCE_COLOR", "3")
	assert.True(t, shouldColor(), "FORCE_COLOR=3 must enable color")
}

func TestShouldColor_AutoDetectTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	os.Unsetenv("FORCE_COLOR")
	prevIsTerminal, prevIsCygwinTerminal := isTerminal, isCygwinTerminal
	defer func() { isTerminal, isCygwinTerminal = prevIsTerminal, prevIsCygwinTerminal }()

	// Both stdout and stderr are terminals -> color enabled
	isTerminal = func(uintptr) bool { return true }
	isCygwinTerminal = func(uintptr) bool { return false }
	assert.True(t, shouldColor(), "TTY stdout and stderr must enable color when no override is set")

	// Stdout is terminal, but stderr is redirected -> color disabled
	isTerminal = func(fd uintptr) bool { return fd == os.Stdout.Fd() }
	assert.False(t, shouldColor(), "redirected stderr must disable color when no override is set")

	// Stderr is terminal, but stdout is redirected -> color disabled
	isTerminal = func(fd uintptr) bool { return fd == os.Stderr.Fd() }
	assert.False(t, shouldColor(), "redirected stdout must disable color when no override is set")

	// Neither is terminal -> color disabled
	isTerminal = func(uintptr) bool { return false }
	assert.False(t, shouldColor(), "non-TTY must disable color when no override is set")

	// Cygwin terminal supported
	isCygwinTerminal = func(uintptr) bool { return true }
	assert.True(t, shouldColor(), "Cygwin terminal must enable color when no override is set")
}

const fixColorSubprocessEnv = "TEST_FIXHANDLER_COLOR_SUBPROCESS"
const fixColorStubTTYEnv = "TEST_FIXHANDLER_STUB_TTY"

func TestColor_Subprocess(t *testing.T) {
	if os.Getenv(fixColorSubprocessEnv) == "1" {
		if os.Getenv(fixColorStubTTYEnv) == "1" {
			isTerminal = func(uintptr) bool { return true }
			isCygwinTerminal = func(uintptr) bool { return false }
		}
		res := newTestResource("Deployment", "api-server", "prod")
		toFix := []ResourceFixInfo{
			{
				Resource:      res,
				FilePath:      "/manifests/deploy.yaml",
				DocumentIndex: 0,
				YamlExpressions: map[string]armotypes.FixPath{
					"spec.replicas": {Path: "spec.replicas", Value: "3"},
				},
			},
		}
		h := &FixHandler{
			fixedControlsCount: 1,
			unfixedControls: []UnfixedControl{
				{
					ControlID:    "C-0012",
					ControlName:  "HostNetwork",
					ResourceKind: "Deployment",
					ResourceName: "api-server",
					FilePath:     "deploy.yaml",
					Reason:       "requires review",
				},
			},
		}
		outChanges := h.formatExpectedChanges(toFix)
		outUnfixed := h.formatUnfixedControls(PhasePlanned)
		fmt.Print(outChanges)
		fmt.Print(outUnfixed)
		os.Exit(0)
	}

	tests := []struct {
		name      string
		env       map[string]string
		stubTTY   bool
		wantColor bool
	}{
		{
			name: "empty NO_COLOR with simulated TTY enables color in fresh process",
			env: map[string]string{
				"NO_COLOR": "",
			},
			stubTTY:   true,
			wantColor: true,
		},
		{
			name: "empty NO_COLOR with FORCE_COLOR=1 enables color in fresh process",
			env: map[string]string{
				"NO_COLOR":    "",
				"FORCE_COLOR": "1",
			},
			stubTTY:   false,
			wantColor: true,
		},
		{
			name: "non-empty NO_COLOR suppresses color despite FORCE_COLOR=1 in fresh process",
			env: map[string]string{
				"NO_COLOR":    "1",
				"FORCE_COLOR": "1",
			},
			stubTTY:   true,
			wantColor: false,
		},
		{
			name: "FORCE_COLOR=-1 enables color in fresh process",
			env: map[string]string{
				"FORCE_COLOR": "-1",
			},
			stubTTY:   false,
			wantColor: true,
		},
		{
			name: "FORCE_COLOR=0 suppresses color in fresh process",
			env: map[string]string{
				"FORCE_COLOR": "0",
			},
			stubTTY:   true,
			wantColor: false,
		},
		{
			name: "non-TTY without overrides suppresses color in fresh process",
			env: map[string]string{
				"NO_COLOR": "",
			},
			stubTTY:   false,
			wantColor: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestColor_Subprocess$") //nolint:gosec // G204: test subprocess re-executes test binary.

			// Construct isolated clean environment for subprocess
			var env []string
			for _, e := range os.Environ() {
				key := strings.SplitN(e, "=", 2)[0]
				if key == "NO_COLOR" || key == "FORCE_COLOR" || key == fixColorSubprocessEnv || key == fixColorStubTTYEnv {
					continue
				}
				env = append(env, e)
			}
			env = append(env, fixColorSubprocessEnv+"=1")
			if tc.stubTTY {
				env = append(env, fixColorStubTTYEnv+"=1")
			}
			for k, v := range tc.env {
				env = append(env, k+"="+v)
			}
			cmd.Env = env

			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))

			outStr := string(out)
			if tc.wantColor {
				assert.Contains(t, outStr, "\x1b[", "expected ANSI escape sequence in output when color is enabled")
				assert.Contains(t, outStr, "File:")
				assert.Contains(t, outStr, "C-0012")
			} else {
				assert.NotContains(t, outStr, "\x1b[", "expected zero ANSI escape sequences in output when color is disabled")
				assert.Contains(t, outStr, "File: /manifests/deploy.yaml")
				assert.Contains(t, outStr, "C-0012")
			}
		})
	}
}

func TestPrintMethods_Color_DirectExecution(t *testing.T) {
	res := newTestResource("Deployment", "api", "default")
	h := &FixHandler{
		fixedControlsCount: 1,
		unfixedControls: []UnfixedControl{
			{
				ControlID:    "C-0001",
				ControlName:  "Name",
				ResourceKind: "Deployment",
				ResourceName: "api",
				FilePath:     "deploy.yaml",
				Reason:       "test reason",
			},
		},
	}

	// Verify executing PrintExpectedChanges and PrintUnfixedControls doesn't panic
	h.PrintExpectedChanges([]ResourceFixInfo{
		{
			Resource: res,
			FilePath: "deploy.yaml",
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {Path: "spec.replicas", Value: "1"},
			},
		},
	})
	h.PrintUnfixedControls(PhasePlanned)
}

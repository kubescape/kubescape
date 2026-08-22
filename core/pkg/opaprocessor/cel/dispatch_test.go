package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mutableFilesystemPod violates C-0017: a Pod whose container does not set
// readOnlyRootFilesystem: true.
func mutableFilesystemPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "mutable", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "c", "image": "nginx"},
			},
		},
	}
}

// readOnlyFilesystemPod satisfies C-0017.
func readOnlyFilesystemPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "readonly", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":            "c",
					"image":           "nginx",
					"securityContext": map[string]any{"readOnlyRootFilesystem": true},
				},
			},
		},
	}
}

// TestEvaluateControlLoadsAndEvaluatesFromBundle proves the facade wires the
// loader to the evaluator: given only a control ID and an object, it loads the
// control's policy from the embedded bundle and returns the right verdict.
func TestEvaluateControlLoadsAndEvaluatesFromBundle(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	t.Run("violating object fails the policy", func(t *testing.T) {
		eval, err := e.EvaluateControl(context.Background(), "C-0017", mutableFilesystemPod(), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		violated := false
		for _, res := range eval.Results {
			require.NoError(t, res.Err)
			if !res.Passed {
				violated = true
				assert.NotEmpty(t, res.Message)
			}
		}
		assert.True(t, violated, "a pod with a mutable root filesystem must violate C-0017")
	})

	t.Run("compliant object passes every validation", func(t *testing.T) {
		eval, err := e.EvaluateControl(context.Background(), "C-0017", readOnlyFilesystemPod(), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		for _, res := range eval.Results {
			require.NoError(t, res.Err)
			assert.True(t, res.Passed)
		}
	})

	t.Run("object outside matchConstraints is not applicable", func(t *testing.T) {
		// C-0017 constrains pods and workload kinds, not ConfigMaps. At admission
		// a ConfigMap is never matched, so the scan must not evaluate it.
		configMap := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "cm", "namespace": "default"},
			"data":       map[string]any{"k": "v"},
		}
		eval, err := e.EvaluateControl(context.Background(), "C-0017", configMap, nil)
		require.NoError(t, err)
		assert.False(t, eval.Applicable, "a ConfigMap is outside C-0017's matchConstraints")
		assert.Empty(t, eval.Results)
	})
}

// TestEvaluateControlUnknownControl proves a control absent from the bundle
// surfaces the loader error rather than a verdict, so the scanner can map it to
// a skipped status instead of a silent pass.
func TestEvaluateControlUnknownControl(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	_, err = e.EvaluateControl(context.Background(), "C-9999", mutableFilesystemPod(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "C-9999")
}

// capabilitiesPod is a Pod whose single container adds the given capabilities.
func capabilitiesPod(name string, caps ...any) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "c",
					"image": "nginx",
					"securityContext": map[string]any{
						"capabilities": map[string]any{"add": caps},
					},
				},
			},
		},
	}
}

// TestEvaluateControlResolvesParamsEndToEnd runs a paramKind control (C-0046)
// through the whole pipeline: bundle load, params resolution from the embedded
// control configuration, and evaluation. Its expressions select
// params.settings.insecureCapabilities with no has() guard, so if params were
// not actually bound the selection would error and every result would carry
// Err — the clean verdicts below are only reachable with the configuration
// resolved for real. TestLoadVAPWithParams covers the loader half in
// isolation; this is the two halves together, which nothing else exercises
// (C-0017 above declares no paramKind).
func TestEvaluateControlResolvesParamsEndToEnd(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	t.Run("capability listed in the embedded params fails the policy", func(t *testing.T) {
		// SYS_ADMIN is in basic-control-configuration.yaml's insecureCapabilities.
		eval, err := e.EvaluateControl(context.Background(), "C-0046", capabilitiesPod("privileged", "SYS_ADMIN"), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		violated := false
		for _, res := range eval.Results {
			require.NoError(t, res.Err, "an eval error here means params did not resolve")
			if !res.Passed {
				violated = true
				assert.NotEmpty(t, res.Message)
			}
		}
		assert.True(t, violated, "a pod adding SYS_ADMIN must violate C-0046")
	})

	t.Run("capability absent from the embedded params passes", func(t *testing.T) {
		// NET_BIND_SERVICE is not in the vendored insecureCapabilities list, so a
		// pass here proves the verdict came from the resolved values rather than
		// from a short-circuit that never read them.
		eval, err := e.EvaluateControl(context.Background(), "C-0046", capabilitiesPod("bind", "NET_BIND_SERVICE"), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		for _, res := range eval.Results {
			require.NoError(t, res.Err, "an eval error here means params did not resolve")
			assert.True(t, res.Passed)
		}
	})
}

// TestEvaluateControlRefusesUnresolvableParams pins the outcome for a control
// taking params the scan cannot resolve (C-0281 reads an ate.dev WorkerPool).
// Before the refusal the ControlConfiguration was bound instead, and the
// params.spec read errored under failurePolicy Fail, so every matching
// ActorTemplate was reported as violating a policy admission never denied.
// An error here is the scanner's skip path, which is the honest answer.
func TestEvaluateControlRefusesUnresolvableParams(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	actorTemplate := map[string]any{
		"apiVersion": "ate.dev/v1alpha1",
		"kind":       "ActorTemplate",
		"metadata":   map[string]any{"name": "agent", "namespace": "default"},
		"spec":       map[string]any{"egress": "marginal"},
	}

	eval, err := e.EvaluateControl(context.Background(), "C-0281", actorTemplate, nil)
	require.Error(t, err, "a control whose params cannot be resolved must be refused, not evaluated")
	assert.Contains(t, err.Error(), "C-0281")
	assert.Contains(t, err.Error(), "WorkerPool")
	assert.Empty(t, eval.Results, "a refused control reports no verdict")
}

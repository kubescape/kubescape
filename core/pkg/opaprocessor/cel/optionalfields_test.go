package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scan binds "object" to the raw scanned manifest, so an omitempty field the
// author left out is simply absent from the map. CEL raises "no such key" on a
// field selection into a missing key, evaluateValidation records that as Err,
// and runCELOnK8s turns "no violation + eval error" into StatusSkipped. A policy
// that walks an optional path without guarding it therefore reports a perfectly
// ordinary workload as Skipped/Unknown rather than Passed.
//
// Live admission hides this: the VAP object there is schema-defaulted, so
// spec.volumes is an empty list and [].all(...) is vacuously true. Offline there
// is no defaulting, so every optional hop needs its own has() guard.
//
// Note has() only guards the final selection: has(a.b.c) still errors when a.b
// is missing. Nested optional paths need a guard per hop.

// bareContainers is a pod spec with nothing optional set: no volumes, no
// securityContext, no per-container securityContext.
func bareContainers() map[string]any {
	return map[string]any{
		"containers": []any{map[string]any{"name": "c", "image": "nginx:1.25"}},
	}
}

// hostPathSpec is a pod spec mounting a hostPath volume with readOnly unset,
// which both C-0045 (readOnly not false) and C-0048 (any hostPath) must flag.
func hostPathSpec() map[string]any {
	return map[string]any{
		"containers": []any{map[string]any{
			"name": "c", "image": "nginx:1.25",
			"volumeMounts": []any{map[string]any{"name": "h", "mountPath": "/host"}},
		}},
		"volumes": []any{map[string]any{
			"name":     "h",
			"hostPath": map[string]any{"path": "/", "type": "Directory"},
		}},
	}
}

func pod(spec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p", "namespace": "default"},
		"spec":     spec,
	}
}

// deployment omits spec.template.metadata: it is optional, and C-0055 used to
// walk into it unguarded.
func deployment(spec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "d", "namespace": "default"},
		"spec":     map[string]any{"template": map[string]any{"spec": spec}},
	}
}

func job(spec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": "j", "namespace": "default"},
		"spec":     map[string]any{"template": map[string]any{"spec": spec}},
	}
}

// cronJob omits spec.jobTemplate.metadata, the common case in a real manifest.
func cronJob(spec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "CronJob",
		"metadata": map[string]any{"name": "cj", "namespace": "default"},
		"spec": map[string]any{
			"schedule":    "* * * * *",
			"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": spec}}},
		},
	}
}

// bundleControlIDs lists every control the vendored bundle ships a policy for.
// TestBundleControlIDsAreCurrent keeps it honest against the bundle itself.
var bundleControlIDs = []string{
	"C-0001", "C-0004", "C-0009", "C-0016", "C-0017", "C-0018", "C-0020", "C-0034",
	"C-0038", "C-0041", "C-0042", "C-0044", "C-0045", "C-0046", "C-0048", "C-0050",
	"C-0055", "C-0056", "C-0057", "C-0061", "C-0062", "C-0073", "C-0074", "C-0075",
	"C-0076", "C-0077", "C-0078", "C-0268", "C-0269", "C-0270", "C-0271",
}

// TestNoEvalErrorOnMinimalWorkloads is the guard for the whole bug class: no
// control in the bundle may eval-error on a valid workload that sets nothing
// optional. An error here means that control silently reports Skipped/Unknown
// instead of a real verdict for the majority of real-world manifests.
//
// It also protects against a re-sync from a cel-admission-library release that
// predates these fixes: `make sync-vap` overwrites the bundle, and this test is
// what catches the regression rather than a user noticing skipped resources.
func TestNoEvalErrorOnMinimalWorkloads(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	objects := map[string]map[string]any{
		"Pod":        pod(bareContainers()),
		"Deployment": deployment(bareContainers()),
		"Job":        job(bareContainers()),
		"CronJob":    cronJob(bareContainers()),
	}

	for kind, obj := range objects {
		for _, id := range bundleControlIDs {
			ev, err := e.EvaluateControl(context.Background(), id, obj, nil)
			if err != nil {
				// The engine refuses policies it cannot honor offline (e.g.
				// matchConditions); the scanner skips the whole rule, which is a
				// separate, already-intentional path.
				continue
			}
			if !ev.Applicable {
				continue
			}
			for i, res := range ev.Results {
				assert.NoErrorf(t, res.Err,
					"%s validation[%d] eval-errored on a minimal %s; the resource would be reported Skipped/Unknown instead of evaluated",
					id, i, kind)
			}
		}
	}
}

// TestHostPathControlsOnVolumelessWorkloads pins the specific verdict, not just
// the absence of an error: a workload with no volumes cannot have a hostPath, so
// both hostPath controls must pass it cleanly.
func TestHostPathControlsOnVolumelessWorkloads(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	objects := map[string]map[string]any{
		"Pod":        pod(bareContainers()),
		"Deployment": deployment(bareContainers()),
		"Job":        job(bareContainers()),
		"CronJob":    cronJob(bareContainers()),
	}

	for _, id := range []string{"C-0045", "C-0048"} {
		for kind, obj := range objects {
			ev, err := e.EvaluateControl(context.Background(), id, obj, nil)
			require.NoError(t, err)
			require.Truef(t, ev.Applicable, "%s must match a %s", id, kind)
			for i, res := range ev.Results {
				require.NoErrorf(t, res.Err, "%s validation[%d] on volume-less %s", id, i, kind)
				assert.Truef(t, res.Passed, "%s validation[%d] must pass a volume-less %s", id, i, kind)
			}
		}
	}
}

// TestHostPathControlsStillDetectViolations is the other half: the guards added
// for the volume-less case must short-circuit only when the path is genuinely
// absent, never when a real hostPath is present.
//
// The CronJob case is the regression that matters most for C-0048, whose guard
// used to test spec.jobTemplate.spec.volumes while the check read
// spec.jobTemplate.spec.template.spec.volumes. That path never exists, so the
// expression always short-circuited to true and a hostPath CronJob was passed:
// a silent false negative, strictly worse than a visible skip.
func TestHostPathControlsStillDetectViolations(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	objects := map[string]map[string]any{
		"Pod":        pod(hostPathSpec()),
		"Deployment": deployment(hostPathSpec()),
		"Job":        job(hostPathSpec()),
		"CronJob":    cronJob(hostPathSpec()),
	}

	for _, id := range []string{"C-0045", "C-0048"} {
		for kind, obj := range objects {
			ev, err := e.EvaluateControl(context.Background(), id, obj, nil)
			require.NoError(t, err)
			require.Truef(t, ev.Applicable, "%s must match a %s", id, kind)

			violated := false
			for i, res := range ev.Results {
				require.NoErrorf(t, res.Err, "%s validation[%d] on hostPath %s", id, i, kind)
				if !res.Passed {
					violated = true
				}
			}
			assert.Truef(t, violated, "%s must flag a %s mounting a hostPath volume", id, kind)
		}
	}
}

// TestC0055ReadsCronJobSecurityContextFromPodSpec covers the other path fix in
// this change: C-0055's CronJob validation read the securityContext from
// spec.jobTemplate.spec, one level above where a pod template actually carries
// it. A CronJob hardened with a pod-level seccompProfile was therefore judged
// only by its per-container securityContext and reported as failing.
func TestC0055ReadsCronJobSecurityContextFromPodSpec(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	spec := bareContainers()
	spec["securityContext"] = map[string]any{
		"seccompProfile": map[string]any{"type": "RuntimeDefault"},
	}

	ev, err := e.EvaluateControl(context.Background(), "C-0055", cronJob(spec), nil)
	require.NoError(t, err)
	require.True(t, ev.Applicable)
	for i, res := range ev.Results {
		require.NoErrorf(t, res.Err, "C-0055 validation[%d]", i)
		assert.Truef(t, res.Passed,
			"C-0055 validation[%d] must accept a CronJob whose pod template sets a seccompProfile", i)
	}
}

// TestBundleControlIDsAreCurrent keeps bundleControlIDs in sync with the bundle,
// so a re-sync that adds controls does not silently leave them out of the
// eval-error sweep above.
func TestBundleControlIDsAreCurrent(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	listed := make(map[string]bool, len(bundleControlIDs))
	for _, id := range bundleControlIDs {
		listed[id] = true
	}
	for id := range catalog.byControl {
		assert.Truef(t, listed[id],
			"control %s is in the bundle but missing from bundleControlIDs; add it so the eval-error sweep covers it", id)
	}
}

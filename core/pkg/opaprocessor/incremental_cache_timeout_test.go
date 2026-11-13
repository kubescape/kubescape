package opaprocessor

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// costlyRule fails every Pod after some CPU-bound work per Pod, so the time a
// control takes grows with the number of evaluations.
const costlyRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	sum(numbers.range(1, 40000)) > 0
	msga := {"alertMessage": "costly", "packagename": "armo_builtins", "alertScore": 1, "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}}
}
`

const costlyPods = 40

func runCostlyControl(t *testing.T, store *scancache.Store, timeout time.Duration) (elapsed time.Duration, timedOut bool, firstPod string) {
	t.Helper()
	control := regoControl("C-COSTLY", "costly", costlyRule, "Pod")
	sess := cautils.NewOPASessionObjMock()
	sess.InfoMap = map[string]apis.StatusInfo{}
	sess.K8SResources = cautils.K8SResources{}
	for i := range costlyPods {
		pod := workloadinterface.NewWorkloadObj(podObject("prod", fmt.Sprintf("p%02d", i), map[string]any{}))
		sess.AllResources[pod.GetID()] = pod
		sess.K8SResources["/v1/pods"] = append(sess.K8SResources["/v1/pods"], pod.GetID())
	}
	policies := &cautils.Policies{Controls: map[string]reporthandling.Control{control.ControlID: control}}
	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	opap.ControlTimeout = timeout
	if store != nil {
		opap.SetIncrementalCache(store)
	}

	start := time.Now()
	require.NoError(t, opap.Process(context.Background(), policies, nil))
	_, timedOut = opap.TimedOutControls[control.ControlID]
	return time.Since(start), timedOut, sess.K8SResources["/v1/pods"][0]
}

// Verifying what to store runs after the control's timed window, so a cold
// incremental scan, which verifies every evaluated object, takes the control
// no closer to ControlTimeout than a full scan does.
//
// The budget is set from the full evaluation time measured here: the control
// fits in it, while evaluating it a second time inside the window does not.
//
// The margin either way is only about a third of the evaluation time, so a
// busy machine can push a single scan over the budget. An attempt in which the
// full scan does not fit says nothing and is retried with a fresh budget, and
// one cold incremental scan that fits and stores its verdicts is enough. With
// verification inside the window the incremental scan runs out of time in
// every attempt, so the test still fails then.
func TestIncrementalCacheVerificationDoesNotCountAgainstControlTimeout(t *testing.T) {
	const attempts = 5
	runCostlyControl(t, nil, 0) // compile and warm up

	for attempt := range attempts {
		var samples []time.Duration
		for range 3 {
			elapsed, _, _ := runCostlyControl(t, nil, 0)
			samples = append(samples, elapsed)
		}
		slices.Sort(samples)
		timeout := samples[1] * 3 / 2
		t.Logf("attempt %d: full evaluation takes %v; ControlTimeout set to %v", attempt, samples[1].Round(time.Millisecond), timeout.Round(time.Millisecond))

		if _, fullTimedOut, _ := runCostlyControl(t, nil, timeout); fullTimedOut {
			t.Logf("attempt %d: the full scan did not fit the budget, so this attempt proves nothing", attempt)
			continue
		}

		store, err := scancache.Load(t.TempDir(), "timeout")
		require.NoError(t, err)
		elapsed, timedOut, pod := runCostlyControl(t, store, timeout)
		t.Logf("attempt %d: cold incremental scan took %v", attempt, elapsed.Round(time.Millisecond))
		if timedOut {
			continue
		}

		object := workloadinterface.NewWorkloadObj(podObject("prod", "p00", map[string]any{}))
		require.Equal(t, object.GetID(), pod)
		_, stored := store.Get("C-COSTLY", pod, scancache.ResourceHash(object.GetObject()))
		assert.True(t, stored, "verified verdicts are still stored")
		return
	}
	t.Fatalf("in %d attempts, no cold incremental scan fit a ControlTimeout that the full scan fit: verification must not count against ControlTimeout", attempts)
}

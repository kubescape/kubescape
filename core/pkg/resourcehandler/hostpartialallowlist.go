package resourcehandler

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// effectiveHostGapAllowlist returns the GVR identities whose host-sensor
// conversion gaps may reach coverage: the dependencies of the effective
// selected controls.
//
// --include-controls/--skip-controls are applied here via the shared control
// filter, because the collection phase runs before the evaluation phase
// narrows the control set. A gap required only by a filtered-out control
// must not penalize the scan. When the filter itself errors (e.g. an include
// that matches nothing), the allowlist falls back to the unfiltered map:
// evaluation re-applies the same filter and fails loudly there with the
// proper message.
//
// No spelling normalization is needed: host identities are virtual
// policy-Kind keys on both sides — DynamicMatch stores the Kind spelling,
// and conversion gaps are emitted under the same spelling even when
// discovery serves the transport CRDs under plural REST names — so plain
// membership is the correct predicate.
func effectiveHostGapAllowlist(sessionObj *cautils.OPASessionObj) map[string]bool {
	allowed := make(map[string]bool)
	if sessionObj == nil {
		return allowed
	}
	effective := cautils.EffectiveControlIDs(sessionObj.Policies, sessionObj.SkipControls, sessionObj.IncludeControls)
	unfiltered := effective == nil
	for gvr, controls := range sessionObj.ResourceToControlsMap {
		if unfiltered {
			allowed[gvr] = true
			continue
		}
		for _, controlID := range controls {
			if _, ok := effective[controlID]; ok {
				allowed[gvr] = true
				break
			}
		}
	}
	return allowed
}

// appendHostSensorPartialPulls records host-sensor conversion gaps the same
// way: the readable envelopes still flow to the scan, while the gap is
// visible as partialGVRPulls instead of vanishing.
//
// Every gap keeps its warning: an unreadable host CRD is always worth
// surfacing. But only gaps in the allowlist — GVRs backing an effective
// selected-control dependency — reach PartialGVRFailures and the coverage
// penalty. CollectResources queries every host resource while the map holds
// only selected policy matches, so an unrelated unreadable CRD must not
// fail --fail-coverage-below when every requested control was fully
// evaluated.
func appendHostSensorPartialPulls(ctx context.Context, sessionObj *cautils.OPASessionObj, partialPulls []cautils.PartialGVRPull, allowed map[string]bool) {
	if len(partialPulls) == 0 {
		return
	}
	for _, p := range partialPulls {
		logger.L().Ctx(ctx).Warning("partial host-sensor collection: some node data may be missing from scan results",
			helpers.String("gvr", p.GVR),
			helpers.String("selector", p.Selector),
			helpers.String("error", p.Error))
		if allowed[p.GVR] {
			sessionObj.PartialGVRFailures = append(sessionObj.PartialGVRFailures, p)
		}
	}
}

package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemediationInfo_IsDryRun(t *testing.T) {
	// default (not confirmed) -> dry-run; --confirm is the only apply switch
	r := &RemediationInfo{}
	assert.True(t, r.IsDryRun())

	// --confirm -> real write
	r = &RemediationInfo{Confirm: true}
	assert.False(t, r.IsDryRun())
}

func TestRemediationInfo_ValidatePayload(t *testing.T) {
	tests := []struct {
		name    string
		info    RemediationInfo
		wantErr bool
	}{
		{"valid annotate", RemediationInfo{Action: "annotate", Kind: "Deployment", Namespace: "payments", Name: "api"}, false},
		{"valid quarantine", RemediationInfo{Action: "quarantine", Kind: "Deployment", Namespace: "payments", Name: "api"}, false},
		{"valid revert", RemediationInfo{Action: "revert", Kind: "Pod", Namespace: "default", Name: "p"}, false},
		{"unknown action", RemediationInfo{Action: "explode", Kind: "Deployment", Namespace: "ns", Name: "a"}, true},
		{"later-phase action", RemediationInfo{Action: "cordon", Kind: "Deployment", Namespace: "ns", Name: "a"}, true},
		{"missing name", RemediationInfo{Action: "annotate", Kind: "Deployment", Namespace: "ns"}, true},
		{"unsupported kind", RemediationInfo{Action: "annotate", Kind: "Service", Namespace: "ns", Name: "a"}, true},
		{"missing namespace", RemediationInfo{Action: "annotate", Kind: "Deployment", Name: "a"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.ValidatePayload(nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRemediationInfo_GetRequestPayload(t *testing.T) {
	r := &RemediationInfo{
		Action:     "annotate",
		Kind:       "Deployment",
		Namespace:  "payments",
		Name:       "api",
		Reason:     "C-0016",
		FindingRef: "workloadconfigurationscansummaries/payments/api",
	}

	payload := r.GetRequestPayload()
	require.Len(t, payload.Commands, 1)
	cmd := payload.Commands[0]
	assert.Equal(t, apis.TypeOperatorAction, cmd.CommandName)

	// round-trips back into the typed contract the operator parses
	args, err := apis.OperatorActionArgsFromMap(cmd.Args)
	require.NoError(t, err)
	assert.Equal(t, apis.OperatorActionAnnotate, args.Action)
	require.NotNil(t, args.Target)
	assert.Equal(t, "Deployment", args.Target.Kind)
	assert.Equal(t, "payments", args.Target.Namespace)
	assert.Equal(t, "api", args.Target.Name)
	assert.Equal(t, "C-0016", args.Reason)
	assert.Equal(t, "workloadconfigurationscansummaries/payments/api", args.FindingRef)

	// dry-run by default
	assert.True(t, args.IsDryRun())

	// the wire verb is exactly "operatorAction" (the constant the operator switches on)
	assert.Equal(t, "operatorAction", string(cmd.CommandName))

	// --confirm produces an explicit dryRun=false the operator treats as apply
	r.Confirm = true
	args, err = apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.False(t, args.IsDryRun())
}

func TestRemediationInfo_GetRequestPayload_Quarantine(t *testing.T) {
	r := &RemediationInfo{
		Action:     "quarantine",
		Kind:       "Deployment",
		Namespace:  "payments",
		Name:       "api",
		Reason:     "C-0016",
		FindingRef: "workloadconfigurationscansummaries/payments/api",
	}

	args, err := apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.Equal(t, apis.OperatorActionQuarantine, args.Action)
	require.NotNil(t, args.Target)
	assert.Equal(t, "Deployment", args.Target.Kind)
	assert.Equal(t, "payments", args.Target.Namespace)
	assert.Equal(t, "api", args.Target.Name)
	assert.Equal(t, "C-0016", args.Reason)
	// dry-run by default; only --confirm applies
	assert.True(t, args.IsDryRun())
	// an explicit target carries no selector, and the CLI never sends a ttl
	// (the operator rejects ttl until auto-revert ships)
	assert.Nil(t, args.Selector)
	assert.Empty(t, args.TTL)

	// --confirm produces an explicit dryRun=false the operator treats as apply
	r.Confirm = true
	args, err = apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.False(t, args.IsDryRun())
}

func TestRemediationInfo_GetRequestPayload_Revert(t *testing.T) {
	r := &RemediationInfo{
		Action:    "revert",
		Kind:      "Pod",
		Namespace: "default",
		Name:      "nginx",
	}

	args, err := apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.Equal(t, apis.OperatorActionRevert, args.Action)
	require.NotNil(t, args.Target)
	assert.Equal(t, "Pod", args.Target.Kind)
	assert.Equal(t, "nginx", args.Target.Name)
	// revert defaults to a dry-run preview too (operator honors it post-#383 fix)
	assert.True(t, args.IsDryRun())
	// an explicit target carries no selector, and the CLI never sends a ttl
	assert.Nil(t, args.Selector)
	assert.Empty(t, args.TTL)
}

func TestRemediationInfo_HasTargetAndSelector(t *testing.T) {
	assert.False(t, (&RemediationInfo{}).HasExplicitTarget())
	assert.False(t, (&RemediationInfo{}).HasSelector())

	// a partial explicit target still counts as one, so validation can report
	// the missing half instead of falling through to "no target given"
	assert.True(t, (&RemediationInfo{Kind: "Deployment"}).HasExplicitTarget())
	assert.True(t, (&RemediationInfo{Name: "api"}).HasExplicitTarget())

	// either selector axis alone is a selector
	assert.True(t, (&RemediationInfo{Control: "C-0016"}).HasSelector())
	assert.True(t, (&RemediationInfo{MinSeverity: "High"}).HasSelector())
}

func TestRemediationInfo_ValidatePayload_Selector(t *testing.T) {
	tests := []struct {
		name    string
		info    RemediationInfo
		wantErr bool
	}{
		{"control only", RemediationInfo{Action: "quarantine", Control: "C-0016"}, false},
		{"min-severity only", RemediationInfo{Action: "quarantine", MinSeverity: "High"}, false},
		{"control and min-severity", RemediationInfo{Action: "quarantine", Control: "C-0016", MinSeverity: "Critical"}, false},
		{"severity is case-insensitive", RemediationInfo{Action: "annotate", MinSeverity: "high"}, false},
		{"severity is trimmed", RemediationInfo{Action: "annotate", MinSeverity: " High "}, false},
		// the operator's severityRank accepts Unknown, so the CLI must too
		{"unknown severity rank is valid", RemediationInfo{Action: "annotate", MinSeverity: "Unknown"}, false},
		// revert by selector re-selects the set that was acted on: a quarantined
		// workload still fails the control that justified quarantining it
		{"revert by selector", RemediationInfo{Action: "revert", Control: "C-0016"}, false},
		{"bogus severity", RemediationInfo{Action: "quarantine", MinSeverity: "Extreme"}, true},
		// selector and explicit target describe different target sets
		{"selector with kind", RemediationInfo{Action: "quarantine", Control: "C-0016", Kind: "Deployment"}, true},
		{"selector with name", RemediationInfo{Action: "quarantine", Control: "C-0016", Name: "api"}, true},
		// the operator ignores selector.namespace, so accepting it would silently
		// widen a namespace-scoped request to the whole cluster
		{"selector with target-namespace", RemediationInfo{Action: "quarantine", Control: "C-0016", Namespace: "payments"}, true},
		{"no target at all", RemediationInfo{Action: "quarantine"}, true},
		// the action is still validated ahead of the target
		{"selector with later-phase action", RemediationInfo{Action: "cordon", Control: "C-0016"}, true},
		{"selector with unknown action", RemediationInfo{Action: "explode", Control: "C-0016"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.ValidatePayload(nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRemediationInfo_GetRequestPayload_Selector(t *testing.T) {
	r := &RemediationInfo{
		Action:      "quarantine",
		Control:     "C-0016",
		MinSeverity: "High",
		Reason:      "CI gate",
	}
	require.NoError(t, r.ValidatePayload(nil))

	args, err := apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.Equal(t, apis.OperatorActionQuarantine, args.Action)

	// the selector reaches the operator's findings-driven targeting verbatim
	require.NotNil(t, args.Selector)
	assert.Equal(t, "C-0016", args.Selector.Control)
	assert.Equal(t, "High", args.Selector.MinSeverity)
	assert.Equal(t, "CI gate", args.Reason)

	// no empty Target rides along: the operator prefers Target when both are
	// set, so an empty one would shadow the selector entirely
	assert.Nil(t, args.Target)

	// dry-run by default, even cluster-wide
	assert.True(t, args.IsDryRun())
	assert.Empty(t, args.TTL)

	// --confirm is still the only thing that applies
	r.Confirm = true
	args, err = apis.OperatorActionArgsFromMap(r.GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.False(t, args.IsDryRun())
	require.NotNil(t, args.Selector)
	assert.Equal(t, "C-0016", args.Selector.Control)
}

func TestRemediationInfo_GetRequestPayload_NoTargetSendsNeither(t *testing.T) {
	// ValidatePayload rejects this, but the payload builder must not invent an
	// empty Target for an unvalidated call — the operator would read it as a
	// request to act on a nameless object rather than erroring cleanly.
	args, err := apis.OperatorActionArgsFromMap((&RemediationInfo{Action: "annotate"}).GetRequestPayload().Commands[0].Args)
	require.NoError(t, err)
	assert.Nil(t, args.Target)
	assert.Nil(t, args.Selector)
	assert.True(t, args.IsDryRun())
}

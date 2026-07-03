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
	// the Phase-1 CLI never sends findings-driven selectors/ttl (operator rejects those)
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
	// no selector/ttl is ever sent by the Phase-1 CLI (operator rejects those)
	assert.Nil(t, args.Selector)
	assert.Empty(t, args.TTL)
}

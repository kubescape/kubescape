package policyhandler

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func Test_validateFramework(t *testing.T) {
	type args struct {
		framework *reporthandling.Framework
	}
	tests := []struct {
		args    args
		name    string
		wantErr bool
	}{
		{
			name: "nil framework",
			args: args{
				framework: nil,
			},
			wantErr: true,
		},
		{
			name: "empty framework",
			args: args{
				framework: &reporthandling.Framework{
					Controls: []reporthandling.Control{},
				},
			},
			wantErr: true,
		},
		{
			name: "none empty framework",
			args: args{
				framework: &reporthandling.Framework{
					Controls: []reporthandling.Control{
						{
							ControlID: "c-0001",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFramework(tt.args.framework); (err != nil) != tt.wantErr {
				t.Errorf("validateControls() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyDownloadError(t *testing.T) {
	tests := []struct {
		err  error
		want error
		name string
		kind string
	}{
		{
			err:  errors.New("Some error"),
			want: errors.New("Some error"),
		},
		{
			err:  errors.New("unsupported protocol scheme"),
			want: fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag"),
		},
		{
			err:  errors.New("framework 'cis' not found"),
			want: fmt.Errorf("framework 'cis' not found, run `kubescape list frameworks` for available frameworks"),
			name: "cis",
			kind: "framework",
		},
		{
			err:  fmt.Errorf("control 'c-0005' not found: %w", getter.ErrControlNotFound),
			want: fmt.Errorf("control 'c-0005' not found, run `kubescape list controls` for available controls"),
			name: "c-0005",
			kind: "control",
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			switch tt.kind {
			case "framework":
				assert.Equal(t, tt.want, frameworkDownloadError(tt.err, tt.name))
			case "control":
				assert.EqualError(t, controlDownloadError(tt.err, tt.name), tt.want.Error())
			default:
				assert.Equal(t, tt.want, frameworkDownloadError(tt.err, tt.name))
				assert.Equal(t, tt.want, controlDownloadError(tt.err, tt.name))
			}
		})
	}
}

// Returns a time.Duration value when PoliciesCacheTtlEnvVar is set and valid.
func TestGetPoliciesCacheTtl_Set(t *testing.T) {
	tests := []struct {
		envVarValue string
		want        time.Duration
	}{
		{
			envVarValue: "10",
			want:        time.Duration(10) * time.Minute,
		},
		{
			envVarValue: "0",
			want:        time.Duration(0),
		},
		{
			envVarValue: "text",
			want:        time.Duration(0),
		},
		{
			envVarValue: "5m",
			want:        5 * time.Minute,
		},
		{
			envVarValue: "90s",
			want:        90 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.envVarValue, func(t *testing.T) {
			t.Setenv(PoliciesCacheTtlEnvVar, tt.envVarValue)

			assert.Equal(t, tt.want, getPoliciesCacheTtl())
		})
	}
}

// Returns 0 when PoliciesCacheTtlEnvVar is not set.
func TestGetPoliciesCacheTtl_NotSet(t *testing.T) {
	want := time.Duration(0)

	assert.Equal(t, want, getPoliciesCacheTtl())
}

func TestPolicyIdentifierToSlice(t *testing.T) {
	tests := []struct {
		policyIdentifier []cautils.PolicyIdentifier
		want             []string
	}{
		{
			policyIdentifier: []cautils.PolicyIdentifier{
				{Kind: "ClusterAdmissionRule", Identifier: "policy1"},
				{Kind: "K8sPSP", Identifier: "policy2"},
			},
			want: []string{"ClusterAdmissionRule: policy1", "K8sPSP: policy2"},
		},
		{
			policyIdentifier: []cautils.PolicyIdentifier{},
			want:             []string{},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.want, policyIdentifierToSlice(tt.policyIdentifier))
		})
	}
}

func TestControlNameOnlyExceptions(t *testing.T) {
	exception := func(name string, policies ...armotypes.PosturePolicy) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: name},
			PosturePolicies: policies,
		}
	}

	exceptions := []armotypes.PostureExceptionPolicy{
		exception("by-name", armotypes.PosturePolicy{ControlName: "HostPath mount"}),
		exception("by-id", armotypes.PosturePolicy{ControlID: "C-0048"}),
		exception("by-name-and-id", armotypes.PosturePolicy{ControlName: "HostPath mount", ControlID: "C-0048"}),
		exception("framework-and-name", armotypes.PosturePolicy{FrameworkName: "NSA", ControlName: "HostPath mount"}),
		exception("rule-and-name", armotypes.PosturePolicy{RuleName: "alert-rw-hostpath", ControlName: "HostPath mount"}),
		exception("one-of-two", armotypes.PosturePolicy{ControlID: "C-0057"}, armotypes.PosturePolicy{ControlName: "HostPath mount"}, armotypes.PosturePolicy{ControlName: "Privileged container"}),
		exception("no-policies"),
		exception("framework-only", armotypes.PosturePolicy{FrameworkName: "NSA"}),
	}

	assert.Equal(t, []string{"by-name", "framework-and-name", "rule-and-name", "one-of-two"}, controlNameOnlyExceptions(exceptions))
	assert.Empty(t, controlNameOnlyExceptions(nil))
}

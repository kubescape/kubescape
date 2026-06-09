package getter

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exceptionsGetterStub struct {
	exceptions []armotypes.PostureExceptionPolicy
	err        error
}

func (s *exceptionsGetterStub) GetExceptions(_ string) ([]armotypes.PostureExceptionPolicy, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.exceptions, nil
}

func TestMergedExceptionsGetter(t *testing.T) {
	tests := []struct {
		name    string
		getter  *MergedExceptionsGetter
		wantLen int
		wantErr bool
	}{
		{
			name:    "nil getter returns empty",
			getter:  nil,
			wantLen: 0,
		},
		{
			name: "primary only",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				nil,
			),
			wantLen: 1,
		},
		{
			name: "merge both",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			),
			wantLen: 2,
		},
		{
			name: "secondary error ignored",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
				&exceptionsGetterStub{err: fmt.Errorf("secondary failed")},
			),
			wantLen: 1,
		},
		{
			name: "primary error returned",
			getter: NewMergedExceptionsGetter(
				&exceptionsGetterStub{err: fmt.Errorf("primary failed")},
				&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.getter.GetExceptions("cluster-a")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, out, tc.wantLen)
		})
	}
}

// posturePolicy builds a posture exception scoping controlID to the given workloads.
func posturePolicy(policyType, controlID string, workloads ...map[string]string) armotypes.PostureExceptionPolicy {
	resources := make([]identifiers.PortalDesignator, 0, len(workloads))
	for _, w := range workloads {
		resources = append(resources, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     w,
		})
	}
	return armotypes.PostureExceptionPolicy{
		PolicyType:      policyType,
		Resources:       resources,
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: controlID}},
	}
}

func nginx(namespace string) map[string]string {
	return map[string]string{
		identifiers.AttributeNamespace: namespace,
		identifiers.AttributeKind:      "Deployment",
		identifiers.AttributeName:      "nginx",
	}
}

func redis(namespace string) map[string]string {
	return map[string]string{
		identifiers.AttributeNamespace: namespace,
		identifiers.AttributeKind:      "Deployment",
		identifiers.AttributeName:      "redis",
	}
}

// TestMergedExceptionsGetter_Deduplication covers the design review's precedence rule:
// cloud/file (primary) exceptions win on overlap, CRD (secondary) exceptions are kept
// only for control+workload pairs not already covered, and partial overlaps keep the
// non-overlapping designators.
func TestMergedExceptionsGetter_Deduplication(t *testing.T) {
	tests := []struct {
		name  string
		cloud []armotypes.PostureExceptionPolicy
		crd   []armotypes.PostureExceptionPolicy
		want  []armotypes.PostureExceptionPolicy
	}{
		{
			name:  "full overlap drops the CRD exception",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", nginx("production"))},
			want:  []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
		},
		{
			name:  "no overlap keeps both exceptions",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", redis("production"))},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				posturePolicy("crd", "C-0034", redis("production")),
			},
		},
		{
			name:  "different control on same workload is not an overlap",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0035", nginx("production"))},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				posturePolicy("crd", "C-0035", nginx("production")),
			},
		},
		{
			name:  "partial overlap keeps only the non-overlapping designators",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", nginx("production"), redis("production"))},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				posturePolicy("crd", "C-0034", redis("production")),
			},
		},
		{
			name:  "CRD exception without resolvable workload keys is kept",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{{PolicyType: "crd", PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}}}},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				{PolicyType: "crd", PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}}},
			},
		},
		{
			name:  "only cloud exceptions",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd:   nil,
			want:  []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
		},
		{
			name:  "only CRD exceptions",
			cloud: nil,
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", nginx("production"))},
			want:  []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", nginx("production"))},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getter := NewMergedExceptionsGetter(
				&exceptionsGetterStub{exceptions: tc.cloud},
				&exceptionsGetterStub{exceptions: tc.crd},
			)
			got, err := getter.GetExceptions("cluster-a")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

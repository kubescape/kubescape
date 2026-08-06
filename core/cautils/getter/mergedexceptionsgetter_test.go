package getter

import (
	"context"
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
	ctx        context.Context
}

func (s *exceptionsGetterStub) GetExceptions(ctx context.Context, _ string) ([]armotypes.PostureExceptionPolicy, error) {
	s.ctx = ctx
	if s.err != nil {
		return nil, s.err
	}
	return s.exceptions, nil
}

func TestMergedExceptionsGetter(t *testing.T) {
	ctx := context.WithValue(context.Background(), "test-key", "test-value")

	tests := []struct {
		name      string
		primary   *exceptionsGetterStub
		secondary *exceptionsGetterStub
		wantLen   int
		wantErr   bool
	}{
		{
			name:    "nil getter returns empty",
			wantLen: 0,
		},
		{
			name:    "primary only",
			primary: &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			wantLen: 1,
		},
		{
			name:      "merge both",
			primary:   &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			secondary: &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			wantLen:   2,
		},
		{
			name:      "secondary error ignored",
			primary:   &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			secondary: &exceptionsGetterStub{err: fmt.Errorf("secondary failed")},
			wantLen:   1,
		},
		{
			name:      "secondary cancellation error returned",
			primary:   &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			secondary: &exceptionsGetterStub{err: context.Canceled},
			wantErr:   true,
		},
		{
			name:      "secondary deadline error returned",
			primary:   &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			secondary: &exceptionsGetterStub{err: context.DeadlineExceeded},
			wantErr:   true,
		},
		{
			name:      "primary error returned",
			primary:   &exceptionsGetterStub{err: fmt.Errorf("primary failed")},
			secondary: &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "crd"}}},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var getter *MergedExceptionsGetter
			if tc.primary == nil && tc.secondary == nil {
				if tc.name != "nil getter returns empty" {
					getter = NewMergedExceptionsGetter(nil, nil)
				}
			} else {
				var p, s IExceptionsGetter
				if tc.primary != nil {
					p = tc.primary
				}
				if tc.secondary != nil {
					s = tc.secondary
				}
				getter = NewMergedExceptionsGetter(p, s)
			}

			got, err := getter.GetExceptions(ctx, "cluster-a")
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, got, tc.wantLen)
			}

			if tc.primary != nil {
				assert.Equal(t, ctx, tc.primary.ctx)
			}
			if tc.secondary != nil && tc.primary != nil && tc.primary.err == nil {
				assert.Equal(t, ctx, tc.secondary.ctx)
			}
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
			got, err := getter.GetExceptions(context.TODO(), "cluster-a")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tests := []struct {
		name      string
		nilGetter bool // exercise the nil-receiver path
		primary   *exceptionsGetterStub
		secondary *exceptionsGetterStub
		wantLen   int
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "nil getter returns empty",
			nilGetter: true,
			wantLen:   0,
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
			wantErrIs: context.Canceled,
		},
		{
			name:      "secondary deadline error returned",
			primary:   &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{{PolicyType: "base"}}},
			secondary: &exceptionsGetterStub{err: context.DeadlineExceeded},
			wantErr:   true,
			wantErrIs: context.DeadlineExceeded,
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
			if !tc.nilGetter {
				// NOTE: assign through typed locals so a nil *exceptionsGetterStub is passed
				// as a nil interface, not a non-nil interface holding a nil pointer.
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
			if tc.wantErrIs != nil {
				require.ErrorIs(t, err, tc.wantErrIs)
			} else if tc.wantErr {
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

func scopedPolicy(policyType string, policy armotypes.PosturePolicy, workloads ...map[string]string) armotypes.PostureExceptionPolicy {
	exception := posturePolicy(policyType, policy.ControlID, workloads...)
	exception.PosturePolicies = []armotypes.PosturePolicy{policy}
	return exception
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
func TestMergedExceptionsGetter_IncludesClusterExceptions(t *testing.T) {
	primary := &exceptionsGetterStub{}

	assert.True(t, NewMergedExceptionsGetter(primary, &exceptionsGetterStub{}).IncludesClusterExceptions())
	assert.False(t, NewMergedExceptionsGetter(primary, nil).IncludesClusterExceptions())

	var unset *MergedExceptionsGetter
	assert.False(t, unset.IncludesClusterExceptions())
}

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
			name:  "multiple policies in CRD exception with partial overlap keeps the non-overlapping policy",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-0034", nginx("production"))},
			crd: []armotypes.PostureExceptionPolicy{
				{
					PolicyType: "crd",
					Resources: []identifiers.PortalDesignator{
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: nginx("production")},
					},
					PosturePolicies: []armotypes.PosturePolicy{
						{ControlID: "C-0034"},
						{ControlID: "C-0035"},
					},
				},
			},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				{
					PolicyType: "crd",
					Resources: []identifiers.PortalDesignator{
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: nginx("production")},
					},
					PosturePolicies: []armotypes.PosturePolicy{
						{ControlID: "C-0035"},
					},
				},
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
			name: "cross deduplication with multiple policies and resources",
			cloud: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				posturePolicy("cloud", "C-0035", redis("production")),
			},
			crd: []armotypes.PostureExceptionPolicy{
				{
					PolicyType: "crd",
					Resources: []identifiers.PortalDesignator{
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: nginx("production")},
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: redis("production")},
					},
					PosturePolicies: []armotypes.PosturePolicy{
						{ControlID: "C-0034"},
						{ControlID: "C-0035"},
					},
				},
			},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-0034", nginx("production")),
				posturePolicy("cloud", "C-0035", redis("production")),
				{
					PolicyType: "crd",
					Resources: []identifiers.PortalDesignator{
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: redis("production")},
					},
					PosturePolicies: []armotypes.PosturePolicy{
						{ControlID: "C-0034"},
					},
				},
				{
					PolicyType: "crd",
					Resources: []identifiers.PortalDesignator{
						{DesignatorType: identifiers.DesignatorAttributes, Attributes: nginx("production")},
					},
					PosturePolicies: []armotypes.PosturePolicy{
						{ControlID: "C-0035"},
					},
				},
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
		{
			// Regression for issue-3367: a cloud exception with no Resources at
			// all applies with no scope constraint (the same "no resources = no
			// scope constraint" convention used for manual controls), so it must
			// subsume a CRD exception for the same control on any workload, not
			// just one that happens to share a resource key.
			name: "scope-less cloud exception subsumes a narrower CRD exception for the same control",
			cloud: []armotypes.PostureExceptionPolicy{{
				PolicyType:      "cloud",
				PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}},
			}},
			crd:  []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0034", nginx("production"))},
			want: []armotypes.PostureExceptionPolicy{{PolicyType: "cloud", PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}}}},
		},
		{
			// The scope-less cloud exception only covers the control it names;
			// a CRD exception for a different control must survive untouched.
			name: "scope-less cloud exception does not subsume a CRD exception for a different control",
			cloud: []armotypes.PostureExceptionPolicy{{
				PolicyType:      "cloud",
				PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}},
			}},
			crd: []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0035", nginx("production"))},
			want: []armotypes.PostureExceptionPolicy{
				{PolicyType: "cloud", PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034"}}},
				posturePolicy("crd", "C-0035", nginx("production")),
			},
		},
		{
			// The primary rule name is an alternation. It has to match the whole
			// CRD rule name, so it does not reach the -v1 rule and the CRD
			// exception must be kept.
			name:  "rule name alternation does not cover a longer CRD rule name",
			cloud: []armotypes.PostureExceptionPolicy{scopedPolicy("cloud", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository|rule-identify-blocklisted-image-registries"}, nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{scopedPolicy("crd", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository-v1"}, nginx("production"))},
			want: []armotypes.PostureExceptionPolicy{
				scopedPolicy("cloud", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository|rule-identify-blocklisted-image-registries"}, nginx("production")),
				scopedPolicy("crd", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository-v1"}, nginx("production")),
			},
		},
		{
			name:  "rule name alternation covers each of its alternatives",
			cloud: []armotypes.PostureExceptionPolicy{scopedPolicy("cloud", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository|rule-identify-blocklisted-image-registries"}, nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{scopedPolicy("crd", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "rule-identify-blocklisted-image-registries"}, nginx("production"))},
			want:  []armotypes.PostureExceptionPolicy{scopedPolicy("cloud", armotypes.PosturePolicy{ControlID: "C-0078", RuleName: "container-image-repository|rule-identify-blocklisted-image-registries"}, nginx("production"))},
		},
		{
			name:  "control ID alternation does not cover a control that only starts with one of them",
			cloud: []armotypes.PostureExceptionPolicy{posturePolicy("cloud", "C-001|C-0034", nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{posturePolicy("crd", "C-0012", nginx("production"))},
			want: []armotypes.PostureExceptionPolicy{
				posturePolicy("cloud", "C-001|C-0034", nginx("production")),
				posturePolicy("crd", "C-0012", nginx("production")),
			},
		},
		{
			name:  "bare wildcard framework name still covers any framework",
			cloud: []armotypes.PostureExceptionPolicy{scopedPolicy("cloud", armotypes.PosturePolicy{FrameworkName: "*", ControlID: "C-0034"}, nginx("production"))},
			crd:   []armotypes.PostureExceptionPolicy{scopedPolicy("crd", armotypes.PosturePolicy{FrameworkName: "NSA", ControlID: "C-0034"}, nginx("production"))},
			want:  []armotypes.PostureExceptionPolicy{scopedPolicy("cloud", armotypes.PosturePolicy{FrameworkName: "*", ControlID: "C-0034"}, nginx("production"))},
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

// TestScopeMatcherAgreesWithProcessor checks that the merge treats a primary scope
// field as covering a CRD one exactly when the exception processor would apply the
// primary exception to that value at evaluation time.
func TestScopeMatcherAgreesWithProcessor(t *testing.T) {
	cases := []struct {
		primary string
		crd     string
		want    bool
	}{
		{primary: "container-image-repository", crd: "container-image-repository", want: true},
		{primary: "Container-Image-Repository", crd: "container-image-repository", want: true},
		{primary: "container-image-repository", crd: "container-image-repository-v1", want: false},
		{primary: "container-image-repository.*", crd: "container-image-repository-v1", want: true},
		{primary: "container-image-repository|rule-identify-blocklisted-image-registries", crd: "container-image-repository", want: true},
		{primary: "container-image-repository|rule-identify-blocklisted-image-registries", crd: "rule-identify-blocklisted-image-registries", want: true},
		{primary: "container-image-repository|rule-identify-blocklisted-image-registries", crd: "container-image-repository-v1", want: false},
		{primary: "container-image-repository|rule-identify-blocklisted-image-registries", crd: "legacy-rule-identify-blocklisted-image-registries", want: false},
		{primary: "*", crd: "any-rule", want: true},
		{primary: "(", crd: "(", want: true},
		{primary: "(", crd: "any-rule", want: false},
	}

	matcher := newScopeMatcher()
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s vs %s", tc.primary, tc.crd), func(t *testing.T) {
			primary := []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{RuleName: tc.primary}}}}
			applies := len(matcher.processor.ListRuleExceptions(primary, "", "", tc.crd)) > 0
			require.Equal(t, tc.want, applies, "processor")
			assert.Equal(t, tc.want, matcher.covers(tc.primary, tc.crd), "scopeMatcher")
		})
	}
}

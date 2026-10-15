package namespaceselector

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestMatchesNamespaceNameRequirements(t *testing.T) {
	for _, tc := range []struct {
		name     string
		operator metav1.LabelSelectorOperator
		values   []string
		want     bool
	}{
		{name: "In matches", operator: metav1.LabelSelectorOpIn, values: []string{"trusted", "platform"}, want: true},
		{name: "In excludes", operator: metav1.LabelSelectorOpIn, values: []string{"other"}},
		{name: "NotIn matches", operator: metav1.LabelSelectorOpNotIn, values: []string{"other"}, want: true},
		{name: "NotIn excludes", operator: metav1.LabelSelectorOpNotIn, values: []string{"trusted"}},
		{name: "Exists matches", operator: metav1.LabelSelectorOpExists, want: true},
		{name: "DoesNotExist excludes", operator: metav1.LabelSelectorOpDoesNotExist},
	} {
		for _, collected := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/uncollected", true: "/collected"}[collected], func(t *testing.T) {
				selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key: corev1.LabelMetadataName, Operator: tc.operator, Values: tc.values,
				}}})
				require.NoError(t, err)
				match, known := Matches(selector, "trusted", nil, collected)
				require.True(t, known)
				require.Equal(t, tc.want, match)
			})
		}
	}
}

func TestMatchesCustomLabelKnowledge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selector  string
		namespace string
		labels    map[string]string
		collected bool
		wantMatch bool
		wantKnown bool
	}{
		{name: "known custom label", selector: "team=platform", namespace: "trusted", labels: map[string]string{"team": "platform"}, collected: true, wantMatch: true, wantKnown: true},
		{name: "known missing custom label", selector: "team=platform", namespace: "trusted", collected: true, wantKnown: true},
		{name: "unknown custom label", selector: "team=platform", namespace: "trusted"},
		{name: "unknown custom absence", selector: "!team", namespace: "trusted"},
		{name: "unknown custom NotIn", selector: "team notin (platform)", namespace: "trusted"},
		{name: "known custom absence", selector: "!team", namespace: "trusted", collected: true, wantMatch: true, wantKnown: true},
		{name: "name only", selector: corev1.LabelMetadataName + "=trusted", namespace: "trusted", wantMatch: true, wantKnown: true},
		{name: "name and unknown label", selector: corev1.LabelMetadataName + "=trusted,team=platform", namespace: "trusted"},
		{name: "wrong name and unknown label", selector: corev1.LabelMetadataName + "=other,team=platform", namespace: "trusted", wantKnown: true},
		{name: "unknown label before wrong name", selector: "aaa=platform," + corev1.LabelMetadataName + "=other", namespace: "trusted", wantKnown: true},
		{name: "empty selector and missing namespace", selector: "", wantMatch: true, wantKnown: true},
		{name: "unknown namespace name", selector: corev1.LabelMetadataName + "=trusted"},
		{name: "negative unknown namespace name", selector: "!" + corev1.LabelMetadataName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := labels.Parse(tc.selector)
			require.NoError(t, err)
			match, known := Matches(selector, tc.namespace, tc.labels, tc.collected)
			require.Equal(t, tc.wantKnown, known)
			require.Equal(t, tc.wantMatch, match)
		})
	}
}

func TestMatchesNeverMutatesLabels(t *testing.T) {
	for _, original := range []map[string]string{nil, {}, {"team": "platform"}, {corev1.LabelMetadataName: "other"}} {
		expected := map[string]string(nil)
		if original != nil {
			expected = make(map[string]string)
			for k, v := range original {
				expected[k] = v
			}
		}
		for _, collected := range []bool{false, true} {
			selector := labels.SelectorFromSet(labels.Set{corev1.LabelMetadataName: "trusted"})
			for i := 0; i < 3; i++ {
				match, known := Matches(selector, "trusted", original, collected)
				require.True(t, known)
				require.True(t, match)
				require.Equal(t, expected, original)
			}
		}
	}
}

func TestMatchesHonorsUnselectableSelector(t *testing.T) {
	for _, collected := range []bool{false, true} {
		match, known := Matches(labels.Nothing(), "trusted", nil, collected)
		require.True(t, known)
		require.False(t, match)
	}
}

func TestMatchesAgreesWithDefaultedNamespace(t *testing.T) {
	// Compare every supported requirement shape with Kubernetes' label evaluator
	// after applying the namespace default. This covers selectors that use the
	// automatic label alongside independent labels rather than replacing them.
	for _, value := range []string{"trusted", "other"} {
		for _, selectorText := range []string{
			corev1.LabelMetadataName + "=trusted",
			corev1.LabelMetadataName + "!=trusted",
			corev1.LabelMetadataName + " in (trusted,platform)",
			corev1.LabelMetadataName + " notin (trusted,platform)",
			corev1.LabelMetadataName,
			"!" + corev1.LabelMetadataName,
			corev1.LabelMetadataName + "=trusted,team=platform",
			corev1.LabelMetadataName + "=trusted,!missing",
			"team=other",
		} {
			t.Run(value+"/"+selectorText, func(t *testing.T) {
				selector, err := labels.Parse(selectorText)
				require.NoError(t, err)
				defaulted := labels.Set{corev1.LabelMetadataName: value, "team": "platform"}
				got, known := Matches(selector, value, map[string]string{"team": "platform"}, true)
				require.True(t, known)
				require.Equal(t, selector.Matches(defaulted), got)
			})
		}
	}
}

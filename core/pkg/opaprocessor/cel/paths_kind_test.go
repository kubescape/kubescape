package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathPlanRetainsDirectTernaryArmGroups(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name: "podSpec",
		Expression: "object.kind == 'Pod' ? object.spec : " +
			"object.kind in ['CronJob'] ? object.spec.jobTemplate.spec.template.spec : object.spec.template.spec",
	}}

	plan := evaluator.buildPathPlan(
		"!has(variables.podSpec.hostNetwork) || variables.podSpec.hostNetwork == false",
		variables,
	)
	require.Len(t, plan.directAlternatives, 1)
	assert.Equal(t, fieldAlternativeGroup{
		{base: "spec", ref: fieldRef{path: "spec.hostNetwork", value: "false"}},
		{base: "spec.jobTemplate.spec.template.spec", ref: fieldRef{path: "spec.jobTemplate.spec.template.spec.hostNetwork", value: "false"}},
		{base: "spec.template.spec", ref: fieldRef{path: "spec.template.spec.hostNetwork", value: "false"}},
	}, plan.directAlternatives[0])
}

func TestPathPlanRecognizesAPIVersionDispatch(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name:       "target",
		Expression: "object.apiVersion == 'v1' ? object.spec : object.spec.template.spec",
	}}

	plan := evaluator.buildPathPlan("variables.target.hostNetwork == false", variables)
	require.Len(t, plan.directAlternatives, 1)
}

func TestPresenceDefaultWithinScopeDispatchRetainsAlternativeGroup(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name: "securityContext",
		Expression: "object.kind == 'Pod' ? " +
			"(has(object.spec.securityContext) ? object.spec.securityContext : {}) : " +
			"object.kind in ['Deployment', 'ReplicaSet', 'DaemonSet', 'StatefulSet', 'Job'] ? " +
			"(has(object.spec.template.spec.securityContext) ? object.spec.template.spec.securityContext : {}) : " +
			"object.kind == 'CronJob' ? " +
			"(has(object.spec.jobTemplate.spec.template.spec.securityContext) ? object.spec.jobTemplate.spec.template.spec.securityContext : {}) : {}",
	}}

	plan := evaluator.buildPathPlan("variables.securityContext.runAsUser == 1000", variables)
	require.Len(t, plan.directAlternatives, 1)
	assert.Equal(t, fieldAlternativeGroup{
		{base: "spec.securityContext", ref: fieldRef{path: "spec.securityContext.runAsUser", value: "1000"}},
		{base: "spec.template.spec.securityContext", ref: fieldRef{path: "spec.template.spec.securityContext.runAsUser", value: "1000"}},
		{base: "spec.jobTemplate.spec.template.spec.securityContext", ref: fieldRef{path: "spec.jobTemplate.spec.template.spec.securityContext.runAsUser", value: "1000"}},
	}, plan.directAlternatives[0])
}

func TestPresenceGuardChoosingDifferentPathsIsNotAScopeDispatch(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name:       "target",
		Expression: "has(object.spec.selector) ? object.spec.deep.nested : object.spec.shallow",
	}}

	plan := evaluator.buildPathPlan("variables.target.flag == false", variables)
	assert.Empty(t, plan.directAlternatives)
}

func TestResolveDirectSelectsTheMostSpecificPresentTernaryBase(t *testing.T) {
	group := fieldAlternativeGroup{
		{base: "spec", ref: fieldRef{path: "spec.hostNetwork", value: "false"}},
		{base: "spec.template.spec", ref: fieldRef{path: "spec.template.spec.hostNetwork", value: "false"}},
		{base: "spec.jobTemplate.spec.template.spec", ref: fieldRef{path: "spec.jobTemplate.spec.template.spec.hostNetwork", value: "false"}},
	}
	plan := pathPlan{
		direct:             []fieldRef{group[0].ref, group[1].ref, group[2].ref},
		directAlternatives: []fieldAlternativeGroup{group},
	}

	tests := []struct {
		name string
		obj  map[string]any
		want fieldRef
	}{
		{name: "pod", obj: podSpecObject("Pod", map[string]any{}), want: group[0].ref},
		{name: "controller", obj: podSpecObject("Deployment", map[string]any{}), want: group[1].ref},
		{name: "shape is selected without a kind table", obj: podSpecObject("ThirdPartyWorkload", map[string]any{}), want: group[1].ref},
		{name: "cron job", obj: podSpecObject("CronJob", map[string]any{}), want: group[2].ref},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []fieldRef{tt.want}, plan.resolveDirect(tt.obj))
		})
	}
}

func TestResolveDirectPreservesAnUnresolvedPartialArmSet(t *testing.T) {
	group := fieldAlternativeGroup{
		{base: "spec.pod", ref: fieldRef{path: "spec.pod.hostNetwork", value: "false"}},
		{base: "spec.controller", ref: fieldRef{path: "spec.controller.hostNetwork", value: "false"}},
	}
	plan := pathPlan{
		direct:             []fieldRef{group[0].ref, group[1].ref},
		directAlternatives: []fieldAlternativeGroup{group},
	}

	assert.Equal(t, []fieldRef{group[1].ref, group[0].ref}, plan.resolveDirect(map[string]any{
		"spec": map[string]any{"cronJob": map[string]any{}},
	}))
}

func TestIndependentFieldsWithTheSameSuffixAreNotAlternatives(t *testing.T) {
	plan := planFor(t, "object.spec.activeDeadlineSeconds == 600 && "+
		"object.spec.template.spec.activeDeadlineSeconds == 600")

	assert.Empty(t, plan.directAlternatives)
	assert.Equal(t, []fieldRef{
		{path: "spec.activeDeadlineSeconds", value: "600"},
		{path: "spec.template.spec.activeDeadlineSeconds", value: "600"},
	}, plan.resolveDirect(podSpecObject("Job", map[string]any{})))
}

func TestNonScopeTernaryPreservesEveryRemediationPath(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name:       "target",
		Expression: "object.spec.replicas > 5 ? object.spec.deep.nested : object.spec.shallow",
	}}
	validations := []Validation{{Expression: "variables.target.flag == false"}}
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "fixture"},
		"spec": map[string]any{
			"replicas": int64(1),
			"deep":     map[string]any{"nested": map[string]any{"flag": false}},
			"shallow":  map[string]any{"flag": true},
		},
	}

	plan := evaluator.buildPathPlan(validations[0].Expression, variables)
	assert.Empty(t, plan.directAlternatives)

	results, err := evaluator.EvaluateOnObject(context.Background(), obj, nil, nil, variables, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	require.NoError(t, results[0].Err)
	assert.ElementsMatch(t, []PathHint{
		{Path: "spec.deep.nested.flag", Value: "false"},
		{Path: "spec.replicas"},
		{Path: "spec.shallow.flag", Value: "false"},
	}, results[0].Paths)
}

func TestVariableTernaryReportsOnlyApplicableRemediationPath(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name: "podSpec",
		Expression: "object.kind == 'Pod' ? object.spec : " +
			"object.kind == 'CronJob' ? object.spec.jobTemplate.spec.template.spec : object.spec.template.spec",
	}}
	validations := []Validation{{
		Expression: "!has(variables.podSpec.hostNetwork) || variables.podSpec.hostNetwork == false",
		Message:    "host networking must be disabled",
	}}

	tests := []struct {
		name string
		obj  map[string]any
		want string
	}{
		{name: "pod", obj: podSpecObject("Pod", map[string]any{"hostNetwork": true}), want: "spec.hostNetwork"},
		{name: "deployment", obj: podSpecObject("Deployment", map[string]any{"hostNetwork": true}), want: "spec.template.spec.hostNetwork"},
		{name: "cron job", obj: podSpecObject("CronJob", map[string]any{"hostNetwork": true}), want: "spec.jobTemplate.spec.template.spec.hostNetwork"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := evaluator.EvaluateOnObject(context.Background(), tt.obj, nil, nil, variables, validations)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.False(t, results[0].Passed)
			require.NoError(t, results[0].Err)
			assert.Equal(t, []PathHint{{Path: tt.want, Value: "false"}}, results[0].Paths)
		})
	}
}

func TestGuardedVariableTernaryReportsOnlyApplicableRemediationPath(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name: "securityContext",
		Expression: "object.kind == 'Pod' ? " +
			"(has(object.spec.securityContext) ? object.spec.securityContext : {}) : " +
			"object.kind in ['Deployment', 'ReplicaSet', 'DaemonSet', 'StatefulSet', 'Job'] ? " +
			"(has(object.spec.template.spec.securityContext) ? object.spec.template.spec.securityContext : {}) : " +
			"object.kind == 'CronJob' ? " +
			"(has(object.spec.jobTemplate.spec.template.spec.securityContext) ? object.spec.jobTemplate.spec.template.spec.securityContext : {}) : {}",
	}}
	validations := []Validation{{Expression: "variables.securityContext.runAsUser == 1000"}}
	obj := podSpecObject("Deployment", map[string]any{
		"securityContext": map[string]any{"runAsUser": int64(0)},
	})

	results, err := evaluator.EvaluateOnObject(context.Background(), obj, nil, nil, variables, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	require.NoError(t, results[0].Err)
	assert.Equal(t, []PathHint{{Path: "spec.template.spec.securityContext.runAsUser", Value: "1000"}}, results[0].Paths)
}

func TestTwoArmTernaryOnCronJobKeepsARemediationPath(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	variables := []Variable{{
		Name:       "podSpec",
		Expression: "object.kind == 'Pod' ? object.spec : object.spec.template.spec",
	}}
	validations := []Validation{{
		Expression: "!has(variables.podSpec.hostNetwork) || variables.podSpec.hostNetwork == false",
	}}
	obj := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": "fixture"},
		"spec": map[string]any{
			"template": map[string]any{"spec": map[string]any{"hostNetwork": true}},
		},
	}

	results, err := evaluator.EvaluateOnObject(context.Background(), obj, nil, nil, variables, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	require.NoError(t, results[0].Err)
	assert.Equal(t, []PathHint{{Path: "spec.template.spec.hostNetwork", Value: "false"}}, results[0].Paths)
}

func TestEndToEndIndependentJobFieldsBothSurvive(t *testing.T) {
	evaluator, err := NewEvaluator()
	require.NoError(t, err)
	validations := []Validation{{
		Expression: "object.spec.activeDeadlineSeconds == 600 && " +
			"object.spec.template.spec.activeDeadlineSeconds == 600",
	}}
	obj := podSpecObject("Job", map[string]any{"activeDeadlineSeconds": int64(30)})
	obj["spec"].(map[string]any)["activeDeadlineSeconds"] = int64(60)

	results, err := evaluator.EvaluateOnObject(context.Background(), obj, nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.ElementsMatch(t, []PathHint{
		{Path: "spec.activeDeadlineSeconds", Value: "600"},
		{Path: "spec.template.spec.activeDeadlineSeconds", Value: "600"},
	}, results[0].Paths)
}

func podSpecObject(kind string, podSpec map[string]any) map[string]any {
	object := map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": "fixture"},
	}
	switch kind {
	case "Pod":
		object["spec"] = podSpec
	case "CronJob":
		object["spec"] = map[string]any{
			"jobTemplate": map[string]any{
				"spec": map[string]any{
					"template": map[string]any{"spec": podSpec},
				},
			},
		}
	default:
		object["spec"] = map[string]any{
			"template": map[string]any{"spec": podSpec},
		}
	}
	return object
}

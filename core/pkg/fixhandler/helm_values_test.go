package fixhandler

import (
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCorrelateFixPathsWithValues(t *testing.T) {
	fixPaths := []armotypes.FixPath{
		{
			Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
			Value: "true",
		},
		{
			Path:  "spec.template.spec.containers[0].securityContext.privileged",
			Value: "false",
		},
		{
			Path:  "spec.replicas",
			Value: "2",
		},
	}

	candidateValues := []string{
		"securityContext.readOnlyRootFilesystem",
		".Values.replicaCount",
		"image.tag",
		"podSecurityContext.privileged",
		"securityContext.privileged",
		"privileged",
	}

	correlated := CorrelateFixPathsWithValues(fixPaths, candidateValues)
	// Must match securityContext.readOnlyRootFilesystem and securityContext.privileged.
	// Must NOT match podSecurityContext.privileged (pod-level anchor / unmatched trailing parent).
	// Must NOT match .Values.replicaCount or bare "privileged" (single-segment ambiguous candidates).
	require.Len(t, correlated, 2)

	assert.Equal(t, "securityContext.readOnlyRootFilesystem", correlated[0].ValuesPath)
	assert.Equal(t, "true", correlated[0].Value)

	assert.Equal(t, "securityContext.privileged", correlated[1].ValuesPath)
	assert.Equal(t, "false", correlated[1].Value)
}

func TestCorrelateFixPathsWithValues_ConflictingValuesExcluded(t *testing.T) {
	fixPaths := []armotypes.FixPath{
		{
			Path:  "spec.template.spec.containers[0].securityContext.privileged",
			Value: "false",
		},
		{
			Path:  "spec.template.spec.containers[1].securityContext.privileged",
			Value: "true",
		},
	}

	candidateValues := []string{
		"securityContext.privileged",
	}

	correlated := CorrelateFixPathsWithValues(fixPaths, candidateValues)
	// Conflicting values for the same ValuesPath must be excluded, not silently overwritten
	assert.Empty(t, correlated)
}

func TestGenerateProposedValuesYAML(t *testing.T) {
	correlated := []CorrelatedValueFix{
		{
			ValuesPath: "securityContext.readOnlyRootFilesystem",
			Value:      "true",
		},
		{
			ValuesPath: "securityContext.runAsNonRoot",
			Value:      "true",
		},
		{
			ValuesPath: "replicaCount",
			Value:      "3",
		},
	}

	yamlStr, err := GenerateProposedValuesYAML(correlated)
	require.NoError(t, err)
	assert.NotEmpty(t, yamlStr)

	var parsed struct {
		ReplicaCount    int `yaml:"replicaCount"`
		SecurityContext struct {
			ReadOnlyRootFilesystem bool `yaml:"readOnlyRootFilesystem"`
			RunAsNonRoot           bool `yaml:"runAsNonRoot"`
		} `yaml:"securityContext"`
	}

	require.NoError(t, yaml.Unmarshal([]byte(yamlStr), &parsed))
	assert.Equal(t, 3, parsed.ReplicaCount)
	assert.True(t, parsed.SecurityContext.ReadOnlyRootFilesystem)
	assert.True(t, parsed.SecurityContext.RunAsNonRoot)
}

func TestPrintHelmSuggestions_UncorrelatedCandidatesPreserved(t *testing.T) {
	s := HelmFixSuggestion{
		ChartName:    "mychart",
		ChartPath:    "/charts/mychart",
		TemplateFile: "templates/deployment.yaml",
		ValuesPaths:  []string{"securityContext.readOnlyRootFilesystem", "replicaCount"},
		FixPaths: []armotypes.FixPath{
			{
				Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
				Value: "true",
			},
			{
				Path:  "spec.replicas",
				Value: "3",
			},
		},
	}

	h := &FixHandler{}
	output := h.formatHelmSuggestions([]HelmFixSuggestion{s})

	// Correlated section should appear for the correlated fix path
	assert.Contains(t, output, "Correlated .Values edits:")
	assert.Contains(t, output, "- .Values.securityContext.readOnlyRootFilesystem = true")
	assert.Contains(t, output, "readOnlyRootFilesystem: true")

	// Because spec.replicas was not correlated, candidate .Values list must NOT be hidden
	assert.Contains(t, output, "Candidate .Values keys referenced by this template:")
	assert.Contains(t, output, "- .Values.replicaCount")
	assert.False(t, strings.Contains(output, "- .Values.securityContext.readOnlyRootFilesystem\n\tEdit"),
		"already correlated keys should not be duplicated in candidate list")
}

// A fix under any of a pod spec's container lists is container-scoped: it is
// matched to the container-level key, never to a pod-level one, even when both
// share the trailing segments.
func TestCorrelateFixPathsWithValues_ContainerListsAvoidPodLevelKeys(t *testing.T) {
	candidates := []string{"pod.securityContext.runAsNonRoot", "securityContext.runAsNonRoot"}
	for _, list := range []string{"containers", "initContainers", "ephemeralContainers"} {
		t.Run(list, func(t *testing.T) {
			fixPaths := []armotypes.FixPath{{
				Path:  "spec.template.spec." + list + "[0].securityContext.runAsNonRoot",
				Value: "true",
			}}
			correlated := CorrelateFixPathsWithValues(fixPaths, candidates)
			require.Len(t, correlated, 1)
			assert.Equal(t, "securityContext.runAsNonRoot", correlated[0].ValuesPath)
		})
	}
}

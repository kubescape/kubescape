package locationresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "..", "..", "examples", "online-boutique")
}

func TestResolveLocation(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "adservice.yaml")
	fixPathToExpectedLineAndColumn := map[string]Location{
		"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem=true":        {Line: 31, Column: 9},
		"spec.template.spec.containers[0].securityContext.runAsNonRoot=true":                  {Line: 31, Column: 9},
		"spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation=false":     {Line: 31, Column: 9},
		"spec.template.spec.containers[0].securityContext.capabilities.drop=NET_RAW":          {Line: 31, Column: 9},
		"spec.template.spec.containers[0].securityContext.seLinuxOptions=YOUR_VALUE":          {Line: 31, Column: 9},
		"spec.template.spec.containers[0].securityContext.seccompProfile=YOUR_VALUE":          {Line: 31, Column: 9},
		"spec.template.spec.securityContext.runAsNonRoot=true":                                {Line: 28, Column: 7},
		"spec.template.spec.securityContext.allowPrivilegeEscalation=false":                   {Line: 28, Column: 7},
		"spec.template.spec.containers[0].securityContext.seccompProfile.type=RuntimeDefault": {Line: 31, Column: 9},
		"spec.template.spec.containers[0].image":                                              {Line: 32, Column: 16},
		"spec.template.spec.containers[0].seccompProfile=YOUR_VALUE":                          {Line: 31, Column: 9},
		"spec.template.spec.containers[0].seLinuxOptions=YOUR_VALUE":                          {Line: 31, Column: 9},
		"spec.template.spec.containers[0].capabilities.drop=YOUR_VALUE":                       {Line: 31, Column: 9},
		"metadata.namespace=YOUR_NAMESPACE":                                                   {Line: 18, Column: 3},
		"metadata.labels=YOUR_VALUE":                                                          {Line: 18, Column: 3},
		"spec.template.metadata.labels=YOUR_VALUE":                                            {Line: 26, Column: 9},
		"spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE":                    {Line: 49, Column: 18},
	}

	resolver, _ := NewFixPathLocationResolver(yamlFilePath)

	for fixPath := range fixPathToExpectedLineAndColumn {
		location, err := resolver.ResolveLocation(fixPath, 100000)
		assert.Contains(t, err.Error(), "node index [100000] out of range ")
		assert.Empty(t, location)
	}

	for fixPath, expected := range fixPathToExpectedLineAndColumn {
		location, err := resolver.ResolveLocation(fixPath, 0)
		assert.NoError(t, err)

		assert.Equalf(t, expected.Line, location.Line, "fixPath %s, expected line: %d, actual line: %d", fixPath, expected.Line, location.Line)
		assert.Equalf(t, expected.Column, location.Column, "fixPath %s, expected column: %d, actual column: %d", fixPath, expected.Column, location.Column)
	}

	fixPathToExpectedLineAndColumn = map[string]Location{
		"metadata.namespace=YOUR_NAMESPACE": {Line: 65, Column: 3},
		"metadata.labels=YOUR_VALUE":        {Line: 65, Column: 3},
	}

	for fixPath, expected := range fixPathToExpectedLineAndColumn {
		location, err := resolver.ResolveLocation(fixPath, 1)
		assert.NoError(t, err)

		assert.Equalf(t, expected.Line, location.Line, "fixPath %s, expected line: %d, actual line: %d", fixPath, expected.Line, location.Line)
		assert.Equalf(t, expected.Column, location.Column, "fixPath %s, expected column: %d, actual column: %d", fixPath, expected.Column, location.Column)
	}
	_, err := resolver.ResolveLocation("some invalid string as an input", 0)
	assert.ErrorContains(t, err, "failed to evaluate yaml expression")
	assert.ErrorContains(t, err, "invalid input")

}

func TestResolveLocation_ZeroCandidateNodesDoesNotPanic(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "adservice.yaml")
	resolver, err := NewFixPathLocationResolver(yamlFilePath)
	assert.NoError(t, err)

	// traversing into a scalar yields zero candidate nodes, which previously
	// caused a nil pointer dereference panic on candidateNodes.Back().
	assert.NotPanics(t, func() {
		location, err := resolver.ResolveLocation("metadata.name.foo=1", 0)
		assert.NoError(t, err)
		assert.Equal(t, Location{Line: 18, Column: 9}, location)
	})
}

func TestFixPathToValidYamlExpression(t *testing.T) {
	tests := []struct {
		name    string
		fixPath string
		want    string
	}{
		{
			name:    "path with no value is prefixed only",
			fixPath: "spec.template.spec.containers[0].image",
			want:    ".spec.template.spec.containers[0].image",
		},
		{
			name:    "value is stripped",
			fixPath: "spec.template.spec.containers[0].securityContext.privileged=true",
			want:    ".spec.template.spec.containers[0].securityContext.privileged",
		},
		{
			name:    "placeholder value is stripped",
			fixPath: "spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE",
			want:    ".spec.template.spec.containers[0].resources.limits.cpu",
		},
		{
			// The CIS control-plane rules emit flag-style fix values that themselves
			// contain "=". Splitting on the last "=" leaves "--anonymous-auth" glued
			// to the path and yields an expression yq cannot evaluate.
			name:    "flag-style value containing = is fully stripped",
			fixPath: "spec.containers[0].command[3]=--anonymous-auth=false",
			want:    ".spec.containers[0].command[3]",
		},
		{
			name:    "value with multiple = is fully stripped",
			fixPath: "spec.containers[0].command[0]=--enable-admission-plugins=NodeRestriction",
			want:    ".spec.containers[0].command[0]",
		},
		{
			name:    "value containing = and a path separator is fully stripped",
			fixPath: "spec.containers[0].command[1]=--encryption-provider-config=/etc/kubernetes/enc.yaml",
			want:    ".spec.containers[0].command[1]",
		},
		{
			name:    "empty value after separator",
			fixPath: "metadata.namespace=",
			want:    ".metadata.namespace",
		},
		{
			name:    "empty input",
			fixPath: "",
			want:    ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FixPathToValidYamlExpression(tt.fixPath))
		})
	}
}

func TestFixPathLocationResolver_NonExistentYaml(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "adservice_invalid.yaml")
	resolver, err := NewFixPathLocationResolver(yamlFilePath)
	assert.Nil(t, resolver)
	assert.NotNil(t, err)
}

func TestFixPathLocationResolver_InvalidYaml(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "invalid.yaml")
	resolver, err := NewFixPathLocationResolver(yamlFilePath)
	assert.Nil(t, resolver)
	assert.NotNil(t, err)
}

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

	for fixPath, _ := range fixPathToExpectedLineAndColumn {
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
	assert.ErrorContains(t, err, "invalid input")

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

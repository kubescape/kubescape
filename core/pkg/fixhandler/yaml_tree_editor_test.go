package fixhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestYAMLTreeEditor(t *testing.T) {
	editor := NewYAMLTreeEditor()

	yamlString := `apiVersion: v1
kind: Pod
metadata:
  name: test
  # This is a comment
spec:
  containers:
  - name: test-container
    image: test-image
`
	fixes := []DocumentFix{
		{
			DocumentIndex: 0,
			Fix: armotypes.FixPath{
				Path:  "spec.containers[0].securityContext.privileged",
				Value: "false",
			},
		},
	}

	result, err := editor.ApplyFixes(yamlString, fixes)
	assert.NoError(t, err)

	expected := `apiVersion: v1
kind: Pod
metadata:
  name: test
  # This is a comment
spec:
  containers:
  - name: test-container
    image: test-image
    securityContext:
      privileged: false
`
	assert.Equal(t, expected, result)
}

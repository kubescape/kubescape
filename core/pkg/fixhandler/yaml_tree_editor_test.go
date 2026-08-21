package fixhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestYAMLTreeEditor(t *testing.T) {
	editor := NewYAMLTreeEditor()

	tests := []struct {
		name        string
		yamlString  string
		fixes       []DocumentFix
		expected    string
		expectError bool
	}{
		{
			name: "basic nested insertion",
			yamlString: `apiVersion: v1
kind: Pod
metadata:
  name: test
  # This is a comment
spec:
  containers:
  - name: test-container
    image: test-image
`,
			fixes: []DocumentFix{
				{
					DocumentIndex: 0,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
			},
			expected: `apiVersion: v1
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
`,
		},
		{
			name: "scalar replacement of quoted values",
			yamlString: `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
    image: "old-image:1.0"
`,
			fixes: []DocumentFix{
				{
					DocumentIndex: 0,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].image",
						Value: "new-image:2.0",
					},
				},
			},
			expected: `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
    image: new-image:2.0
`,
		},
		{
			name: "fixes targeting document index 1 or higher in multi-document YAML",
			yamlString: `apiVersion: v1
kind: Service
metadata:
  name: svc
---
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
`,
			fixes: []DocumentFix{
				{
					DocumentIndex: 1,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
			},
			expected: `apiVersion: v1
kind: Service
metadata:
  name: svc
---
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
    securityContext:
      privileged: false
`,
		},
		{
			name: "multiple sequential fixes",
			yamlString: `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
`,
			fixes: []DocumentFix{
				{
					DocumentIndex: 0,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
				{
					DocumentIndex: 0,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.runAsNonRoot",
						Value: "true",
					},
				},
			},
			expected: `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test-container
    securityContext:
      privileged: false
      runAsNonRoot: true
`,
		},
		{
			name:       "CRLF input with preserved newline style",
			yamlString: "apiVersion: v1\r\nkind: Pod\r\nmetadata:\r\n  name: test\r\nspec:\r\n  containers:\r\n  - name: test-container\r\n",
			fixes: []DocumentFix{
				{
					DocumentIndex: 0,
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
			},
			expected: "apiVersion: v1\r\nkind: Pod\r\nmetadata:\r\n  name: test\r\nspec:\r\n  containers:\r\n  - name: test-container\r\n    securityContext:\r\n      privileged: false\r\n",
		},
		{
			name: "silently skipped out-of-range or empty documents",
			yamlString: `apiVersion: v1
kind: Pod
metadata:
  name: test
---
---
# empty doc above
`,
			fixes: []DocumentFix{
				{
					DocumentIndex: 5, // out of range
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
				{
					DocumentIndex: 1, // empty doc
					Fix: armotypes.FixPath{
						Path:  "spec.containers[0].securityContext.privileged",
						Value: "false",
					},
				},
			},
			expected: `apiVersion: v1
kind: Pod
metadata:
  name: test
---
---
# empty doc above
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := editor.ApplyFixes(tc.yamlString, tc.fixes)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

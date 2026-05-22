package anonymizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapping_GetOrCreate(t *testing.T) {
	tests := []struct {
		name     string
		prefixA  string
		valueA   string
		prefixB  string
		valueB   string
		validate func(t *testing.T, first, second string)
	}{
		{
			name:    "same input should return same output",
			prefixA: "res",
			valueA:  "my-pod",
			prefixB: "res",
			valueB:  "my-pod",
			validate: func(t *testing.T, first, second string) {
				assert.Equal(t, first, second)
			},
		},
		{
			name:    "different inputs should return different outputs",
			prefixA: "res",
			valueA:  "pod-a",
			prefixB: "res",
			valueB:  "pod-b",
			validate: func(t *testing.T, first, second string) {
				assert.NotEqual(t, first, second)
			},
		},
		{
			name:    "different prefixes should isolate mappings",
			prefixA: "res",
			valueA:  "same-value",
			prefixB: "ns",
			valueB:  "same-value",
			validate: func(t *testing.T, first, second string) {
				assert.NotEqual(t, first, second)
			},
		},
		{
			name:    "empty value should still produce deterministic mapping",
			prefixA: "res",
			valueA:  "",
			prefixB: "res",
			valueB:  "",
			validate: func(t *testing.T, first, second string) {
				assert.Equal(t, first, second)
				assert.Contains(t, first, "res-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()

			first := mapping.GetOrCreate(test.prefixA, test.valueA)
			second := mapping.GetOrCreate(test.prefixB, test.valueB)

			test.validate(t, first, second)
		})
	}
}

func TestMapping_GetOrCreate_PrefixIsolationAcrossMultiplePrefixes(t *testing.T) {
	mapping := NewMapping()

	resource := mapping.GetOrCreate("res", "same-value")
	namespace := mapping.GetOrCreate("ns", "same-value")
	label := mapping.GetOrCreate("lbl", "same-value")

	assert.NotEqual(t, resource, namespace)
	assert.NotEqual(t, resource, label)
	assert.NotEqual(t, namespace, label)
}

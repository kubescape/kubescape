package anonymizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMappingTransformer(t *testing.T) {
	t.Parallel()

	transformer := NewMappingTransformer()

	require.NotNil(t, transformer)
	require.NotNil(t, transformer.mapping)
	require.NotNil(t, transformer.mapping.data)
	assert.Empty(t, transformer.mapping.data)
	require.NotNil(t, transformer.mapping.seen)
	assert.Empty(t, transformer.mapping.seen)
}

func TestMappingTransformer_Transform(t *testing.T) {
	t.Parallel()

	// Fixed SHA-256 vectors check the output independently of Mapping.
	const (
		podHash   = "a41257b1030f6942400e636942da77a2"
		emptyHash = "e3b0c44298fc1c149afbf4c8996fb924"
	)
	tests := []struct {
		name   string
		prefix string
		value  string
		want   string
	}{
		{name: "resource", prefix: "res", value: "my-pod", want: "res-" + podHash},
		{name: "different prefix", prefix: "ref", value: "my-pod", want: "ref-" + podHash},
		{name: "empty prefix", value: "my-pod", want: "-" + podHash},
		{name: "empty value", prefix: "res", want: "res-" + emptyHash},
		{name: "empty prefix and value", want: "-" + emptyHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewMappingTransformer().Transform(tt.prefix, tt.value)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMappingTransformer_Transform_Deterministic(t *testing.T) {
	t.Parallel()

	transformer := NewMappingTransformer()
	first, err := transformer.Transform("res", "my-pod")
	require.NoError(t, err)

	other, err := transformer.Transform("res", "another-pod")
	require.NoError(t, err)
	assert.NotEqual(t, first, other)

	repeated, err := transformer.Transform("res", "my-pod")
	require.NoError(t, err)
	assert.Equal(t, first, repeated)

	independent, err := NewMappingTransformer().Transform("res", "my-pod")
	require.NoError(t, err)
	assert.Equal(t, first, independent)
}

func TestMappingTransformer_Transform_DifferentPrefixes(t *testing.T) {
	t.Parallel()

	transformer := NewMappingTransformer()
	resource, err := transformer.Transform("res", "my-pod")
	require.NoError(t, err)

	reference, err := transformer.Transform("ref", "my-pod")
	require.NoError(t, err)
	assert.NotEqual(t, resource, reference)

	repeated, err := transformer.Transform("res", "my-pod")
	require.NoError(t, err)
	assert.Equal(t, resource, repeated)
}

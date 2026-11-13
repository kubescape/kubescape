package locationresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	resolver, _ := NewPathLocationResolver(yamlFilePath)

	for fixPath := range fixPathToExpectedLineAndColumn {
		location, err := resolver.ResolveLocation(fixPath, 100000)
		assert.Contains(t, err.Error(), "node index [100000] out of range ")
		assert.Empty(t, location)
	}

	// Negative node indices must be rejected, not passed to the slice.
	for fixPath := range fixPathToExpectedLineAndColumn {
		location, err := resolver.ResolveLocation(fixPath, -1)
		assert.Contains(t, err.Error(), "node index [-1] out of range ")
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
	// A string that is not a path is refused rather than resolved: its spaces
	// are outside the key alphabet, so it is reported as malformed instead of
	// being looked up as a key that happens not to exist.
	location, err := resolver.ResolveLocation("some invalid string as an input", 0)
	assert.ErrorIs(t, err, pathparse.ErrMalformedPath)
	assert.Equal(t, Location{}, location)
}

func TestResolveLocation_ZeroCandidateNodesDoesNotPanic(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "adservice.yaml")
	resolver, err := NewPathLocationResolver(yamlFilePath)
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
			want:    `.["spec"]["template"]["spec"]["containers"][0]["image"]`,
		},
		{
			name:    "value is stripped",
			fixPath: "spec.template.spec.containers[0].securityContext.privileged=true",
			want:    `.["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"]`,
		},
		{
			name:    "placeholder value is stripped",
			fixPath: "spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE",
			want:    `.["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"]`,
		},
		{
			// The CIS control-plane rules emit flag-style fix values that themselves
			// contain "=". Splitting on the last "=" leaves "--anonymous-auth" glued
			// to the path and yields an expression yq cannot evaluate.
			name:    "flag-style value containing = is fully stripped",
			fixPath: "spec.containers[0].command[3]=--anonymous-auth=false",
			want:    `.["spec"]["containers"][0]["command"][3]`,
		},
		{
			name:    "value with multiple = is fully stripped",
			fixPath: "spec.containers[0].command[0]=--enable-admission-plugins=NodeRestriction",
			want:    `.["spec"]["containers"][0]["command"][0]`,
		},
		{
			name:    "value containing = and a path separator is fully stripped",
			fixPath: "spec.containers[0].command[1]=--encryption-provider-config=/etc/kubernetes/enc.yaml",
			want:    `.["spec"]["containers"][0]["command"][1]`,
		},
		{
			name:    "empty value after separator",
			fixPath: "metadata.namespace=",
			want:    `.["metadata"]["namespace"]`,
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

func TestPathLocationResolver_NonExistentYaml(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "adservice_invalid.yaml")
	resolver, err := NewPathLocationResolver(yamlFilePath)
	assert.Nil(t, resolver)
	assert.NotNil(t, err)
}

func TestPathLocationResolver_InvalidYaml(t *testing.T) {
	yamlFilePath := filepath.Join(onlineBoutiquePath(), "invalid.yaml")
	resolver, err := NewPathLocationResolver(yamlFilePath)
	assert.Nil(t, resolver)
	assert.NotNil(t, err)
}

func TestNewPathLocationResolver_OversizedManifestRejected(t *testing.T) {
	t.Setenv(maxFileSizeEnvVar, "")
	dir := t.TempDir()
	filePath := filepath.Join(dir, "oversized.yaml")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(defaultMaxFileSize+1))
	require.NoError(t, f.Close())

	resolver, err := NewPathLocationResolver(filePath)
	assert.Nil(t, resolver)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestTooLarge)
}

func TestNewPathLocationResolver_NonRegularManifestRejected(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err == nil {
		dir := t.TempDir()
		symlink := filepath.Join(dir, "dev_null.yaml")
		require.NoError(t, os.Symlink("/dev/null", symlink))

		resolver, err := NewPathLocationResolver(symlink)
		assert.Nil(t, resolver)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	}
}

func TestNewPathLocationResolver_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	resolver, err := NewPathLocationResolver(dir)
	assert.Nil(t, resolver)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestNotRegular)
}

func TestNewPathLocationResolver_MaxFileSizeEnvVar(t *testing.T) {
	const validYAML = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"

	t.Run("lower override rejects manifest", func(t *testing.T) {
		t.Setenv(maxFileSizeEnvVar, "10")
		dir := t.TempDir()
		filePath := filepath.Join(dir, "test.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(validYAML), 0o600)) // len > 10

		resolver, err := NewPathLocationResolver(filePath)
		assert.Nil(t, resolver)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestTooLarge)
	})

	t.Run("higher override permits manifest", func(t *testing.T) {
		t.Setenv(maxFileSizeEnvVar, "1000")
		dir := t.TempDir()
		filePath := filepath.Join(dir, "test.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(validYAML), 0o600))

		resolver, err := NewPathLocationResolver(filePath)
		require.NoError(t, err)
		assert.NotNil(t, resolver)
	})
}

func TestNewPathLocationResolver_MaxInt64FallsBackToDefault(t *testing.T) {
	t.Setenv(maxFileSizeEnvVar, "9223372036854775807")
	assert.Equal(t, int64(defaultMaxFileSize), getMaxFileSize(), "math.MaxInt64 must fall back to default to avoid overflow")

	dir := t.TempDir()
	filePath := filepath.Join(dir, "valid.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"), 0o600))

	resolver, err := NewPathLocationResolver(filePath)
	require.NoError(t, err)
	assert.NotNil(t, resolver)
}

func TestGetMaxFileSize_InvalidFallback(t *testing.T) {
	t.Run("non-numeric value falls back to default", func(t *testing.T) {
		t.Setenv(maxFileSizeEnvVar, "invalid")
		assert.Equal(t, int64(defaultMaxFileSize), getMaxFileSize())
	})

	t.Run("negative value falls back to default", func(t *testing.T) {
		t.Setenv(maxFileSizeEnvVar, "-100")
		assert.Equal(t, int64(defaultMaxFileSize), getMaxFileSize())
	})

	t.Run("zero value falls back to default", func(t *testing.T) {
		t.Setenv(maxFileSizeEnvVar, "0")
		assert.Equal(t, int64(defaultMaxFileSize), getMaxFileSize())
	})
}

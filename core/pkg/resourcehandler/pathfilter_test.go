package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func podPolicyFramework() reporthandling.Framework {
	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"pods"},
	}
	return *mockFramework("path-filter-input", []reporthandling.Control{
		mockControl("path-filter-input", []reporthandling.PolicyRule{
			mockRule("path-filter-input", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})
}

func writePodManifest(t *testing.T, path, name string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: default\n"
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0o600))
}

func scannedPodNames(t *testing.T, scanInfo *cautils.ScanInfo) []string {
	t.Helper()

	session := cautils.NewOPASessionObj(
		context.Background(), []reporthandling.Framework{podPolicyFramework()}, nil, scanInfo, nil,
	)
	_, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)

	names := make([]string, 0, len(allResources))
	for _, resource := range allResources {
		names = append(names, resource.GetName())
	}
	return names
}

func TestFileResourceHandlerExcludesPathsFromIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writePodManifest(t, filepath.Join(root, "pod.yaml"), "scanned")
	writePodManifest(t, filepath.Join(root, "testdata", "pod.yaml"), "fixture")
	require.NoError(t, os.WriteFile(filepath.Join(root, cautils.IgnoreFileName), []byte("testdata/\n"), 0o600))

	names := scannedPodNames(t, &cautils.ScanInfo{InputPatterns: []string{root}})

	assert.Equal(t, []string{"scanned"}, names)
}

func TestFileResourceHandlerExcludesPathsFromFlag(t *testing.T) {
	root := t.TempDir()
	writePodManifest(t, filepath.Join(root, "pod.yaml"), "scanned")
	writePodManifest(t, filepath.Join(root, "generated", "deep", "pod.yaml"), "generated")

	names := scannedPodNames(t, &cautils.ScanInfo{
		InputPatterns: []string{root},
		ExcludePaths:  []string{"generated/**"},
	})

	assert.Equal(t, []string{"scanned"}, names)
}

func TestFileResourceHandlerReIncludesNegatedPath(t *testing.T) {
	root := t.TempDir()
	writePodManifest(t, filepath.Join(root, "test", "prod.yaml"), "prod")
	writePodManifest(t, filepath.Join(root, "test", "dev.yaml"), "dev")

	names := scannedPodNames(t, &cautils.ScanInfo{
		InputPatterns: []string{root},
		ExcludePaths:  []string{"test/**", "!test/prod.yaml"},
	})

	assert.Equal(t, []string{"prod"}, names)
}

func TestFileResourceHandlerHonorsNoIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writePodManifest(t, filepath.Join(root, "pod.yaml"), "scanned")
	writePodManifest(t, filepath.Join(root, "testdata", "pod.yaml"), "fixture")
	require.NoError(t, os.WriteFile(filepath.Join(root, cautils.IgnoreFileName), []byte("testdata/\n"), 0o600))

	names := scannedPodNames(t, &cautils.ScanInfo{
		InputPatterns: []string{root},
		NoIgnoreFile:  true,
	})

	assert.ElementsMatch(t, []string{"scanned", "fixture"}, names)
}

func TestPathFilterFromScanInfo(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, cautils.IgnoreFileName), []byte("testdata/\n"), 0o600))

	t.Run("combines the ignore file with the flag patterns", func(t *testing.T) {
		filter, err := pathFilterFromScanInfo(context.Background(), root, &cautils.ScanInfo{
			ExcludePaths: []string{"*.tmpl.yaml"},
		})
		require.NoError(t, err)
		require.NotNil(t, filter)

		assert.Equal(t, []string{"testdata/", "*.tmpl.yaml"}, filter.Patterns())
	})

	t.Run("rejects a malformed pattern", func(t *testing.T) {
		filter, err := pathFilterFromScanInfo(context.Background(), root, &cautils.ScanInfo{
			ExcludePaths: []string{"pod[.yaml"},
		})
		require.ErrorIs(t, err, cautils.ErrInvalidIgnorePattern)
		assert.Nil(t, filter)
	})

	t.Run("returns no filter without a scan info", func(t *testing.T) {
		filter, err := pathFilterFromScanInfo(context.Background(), root, nil)
		require.NoError(t, err)
		assert.Nil(t, filter)
	})
}

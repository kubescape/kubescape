package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Initializes a new instance of FileResourceHandler.
func TestNewFileResourceHandler_InitializesNewInstance(t *testing.T) {
	fileHandler := NewFileResourceHandler()
	assert.NotNil(t, fileHandler)
}

// Deduplicates resources discovered by both kustomize render and the plain-YAML glob.
func TestGetResourcesFromPath_DeduplicatesKustomizeAndPlainYaml(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/base", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var deployments []string
	for _, w := range workloads {
		if w.GetKind() == "Deployment" {
			deployments = append(deployments, w.GetID())
		}
	}

	require.Len(t, deployments, 1)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, workloadIDToSource[deployments[0]].FileType)
}

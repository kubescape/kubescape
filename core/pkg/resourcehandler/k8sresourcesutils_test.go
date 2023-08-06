package resourcehandler

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestSsEmptyImgVulns(t *testing.T) {
	externalResourcesMap := make(cautils.ExternalResources, 0)
	externalResourcesMap["container.googleapis.com/v1"] = []string{"fsdfds"}
	assert.Equal(t, true, isEmptyImgVulns(externalResourcesMap))

	externalResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{"dada"}
	assert.Equal(t, false, isEmptyImgVulns(externalResourcesMap))

	externalResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{}
	externalResourcesMap["bla"] = []string{"blu"}
	assert.Equal(t, true, isEmptyImgVulns(externalResourcesMap))
}

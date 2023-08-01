package resourcehandler

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestSsEmptyImgVulns(t *testing.T) {
	ksResourcesMap := make(cautils.KSResources, 0)
	ksResourcesMap["container.googleapis.com/v1"] = []string{"fsdfds"}
	assert.Equal(t, true, isEmptyImgVulns(ksResourcesMap))

	ksResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{"dada"}
	assert.Equal(t, false, isEmptyImgVulns(ksResourcesMap))

	ksResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{}
	ksResourcesMap["bla"] = []string{"blu"}
	assert.Equal(t, true, isEmptyImgVulns(ksResourcesMap))
}

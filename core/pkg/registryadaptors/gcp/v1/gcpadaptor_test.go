package v1

import (
	"testing"

	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestSum(t *testing.T) {
	var err error
	var adaptor registryvulnerabilities.IContainerImageVulnerabilityAdaptor

	adaptor, err = NewGCPAdaptorMock()
	assert.NoError(t, err)

	assert.NoError(t, adaptor.Login())

	imageVulnerabilityReports, err := adaptor.GetImagesVulnerabilities([]registryvulnerabilities.ContainerImageIdentifier{{Tag: "gcr.io/myproject/nginx@sha256:1XXXXX"}, {Tag: "gcr.io/myproject/nginx@sha256:2XXXXX"}})
	assert.NoError(t, err)

	for i := range imageVulnerabilityReports {
		var length int
		if i == 0 {
			length = 5
		} else if i == 1 {
			length = 3
		}
		assert.Equal(t, length, len(imageVulnerabilityReports[i].Vulnerabilities))
	}
}

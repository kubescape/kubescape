package v1

import (
	"testing"

	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestSum(t *testing.T) {
	var err error
	var adaptor registryvulnerabilities.IContainerImageVulnerabilityAdaptor

	adaptor, err = NewArmoAdaptorMock()
	assert.NoError(t, err)

	assert.NoError(t, adaptor.Login())

	imageVulnerabilityReport, err := adaptor.GetImageVulnerability(&registryvulnerabilities.ContainerImageIdentifier{Tag: "gke.gcr.io/gcp-compute-persistent-disk-csi-driver:v1.3.4-gke.0"})
	assert.NoError(t, err)

	assert.Equal(t, 25, len(imageVulnerabilityReport.Vulnerabilities))
}

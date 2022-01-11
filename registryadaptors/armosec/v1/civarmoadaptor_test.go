package v1

import (
	"fmt"
	"testing"

	"github.com/armosec/kubescape/registryadaptors/registryvulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestSum(t *testing.T) {
	credentials := make(map[string]string)
	credentials["clientId"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	credentials["accessKey"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	credentials["accountId"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

	var err error
	var adaptor registryvulnerabilities.IContainerImageVulnerabilityAdaptor

	adaptor, err = NewArmoAdaptorMock("armoui-dev.eudev3.cyberarmorsoft.com", credentials)
	assert.NoError(t, err)

	assert.NoError(t, adaptor.Login())
	//fmt.Printf("Login successful: %s\n", adaptor.feToken.Token)

	imageVulnerabilityReport, err := adaptor.GetImageVulnerability(&registryvulnerabilities.ContainerImageIdentifier{Tag: "gke.gcr.io/gcp-compute-persistent-disk-csi-driver:v1.3.4-gke.0"})
	assert.NoError(t, err)

	for _, vulnerability := range imageVulnerabilityReport.Vulnerabilities {
		fmt.Printf("%s: %s\n", vulnerability.Name, vulnerability.Description)
	}
}

/*

func TestSum(t *testing.T) {
	credentials := make(map[string]string)
	credentials["clientId"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	credentials["accessKey"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	credentials["accountId"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

	var err error
	var adaptor registryvulnerabilities.IContainerImageVulnerabilityAdaptor

	adaptor, err = NewArmoAdaptorMock("armoui-dev.eudev3.cyberarmorsoft.com", credentials)
	assert.NoError(t, err)

	// TODO - create mock
	assert.NoError(t, adaptor.Login())
	//fmt.Printf("Login successful: %s\n", adaptor.feToken.Token)

	imageVulnerabilityReport, err := adaptor.GetImageVulnerability(&registryvulnerabilities.ContainerImageIdentifier{Tag: "gke.gcr.io/gcp-compute-persistent-disk-csi-driver:v1.3.4-gke.0"})
	assert.NoError(t, err)

	for _, vulnerability := range imageVulnerabilityReport.Vulnerabilities {
		fmt.Printf("%s: %s\n", vulnerability.Name, vulnerability.Description)
	}
}

*/

package resourcehandler

import (
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
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

func Test_getWorkloadFromScanObject(t *testing.T) {
	// nil input returns nil without error
	workload, err := getWorkloadFromScanObject(nil)
	assert.NoError(t, err)
	assert.Nil(t, workload)

	// valid input returns workload without error
	workload, err = getWorkloadFromScanObject(&objectsenvelopes.ScanObject{
		ApiVersion: "apps/v1",
		Kind:       "Deployment",
		Metadata: objectsenvelopes.ScanObjectMetadata{
			Name:      "test-deployment",
			Namespace: "test-ns",
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, workload)
	assert.Equal(t, "test-ns", workload.GetNamespace())
	assert.Equal(t, "test-deployment", workload.GetName())
	assert.Equal(t, "Deployment", workload.GetKind())
	assert.Equal(t, "apps/v1", workload.GetApiVersion())

	// invalid input returns an error
	workload, err = getWorkloadFromScanObject(&objectsenvelopes.ScanObject{
		ApiVersion: "apps/v1",
		// missing kind
		Metadata: objectsenvelopes.ScanObjectMetadata{
			Name:      "test-deployment",
			Namespace: "test-ns",
		},
	})
	assert.Error(t, err)
	assert.Nil(t, workload)
}

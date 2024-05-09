package vap_helper

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
)

func TestGetVapHelperCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetFixCmd function
	_ = GetVapHelperCmd(mockKubescape)

}

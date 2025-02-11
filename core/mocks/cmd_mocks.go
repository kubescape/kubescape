package mocks

import (
	"context"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
)

type MockIKubescape struct{}

func (m *MockIKubescape) Context() context.Context {
	return context.TODO()
}

func (m *MockIKubescape) Scan(scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	return nil, nil
}

func (m *MockIKubescape) List(listPolicies *metav1.ListPolicies) error {
	return nil
}

func (m *MockIKubescape) Download(downloadInfo *metav1.DownloadInfo) error {
	return nil
}

func (m *MockIKubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {
	return nil
}

func (m *MockIKubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	return nil
}

func (m *MockIKubescape) DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error {
	return nil
}

func (m *MockIKubescape) Fix(fixInfo *metav1.FixInfo) error {
	return nil
}

func (m *MockIKubescape) Patch(patchInfo *metav1.PatchInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	return nil, nil
}

func (m *MockIKubescape) ScanImage(imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	return nil, nil
}

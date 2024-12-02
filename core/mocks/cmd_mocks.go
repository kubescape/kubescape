package mocks

import (
	"context"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
)

type MockIKubescape struct{}

func (m *MockIKubescape) Scan(ctx context.Context, scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	return nil, nil
}

func (m *MockIKubescape) List(ctx context.Context, listPolicies *metav1.ListPolicies) error {
	return nil
}

func (m *MockIKubescape) Download(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	return nil
}

func (m *MockIKubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {
	return nil
}

func (m *MockIKubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	return nil
}

func (m *MockIKubescape) DeleteCachedConfig(ctx context.Context, deleteConfig *metav1.DeleteConfig) error {
	return nil
}

func (m *MockIKubescape) Fix(ctx context.Context, fixInfo *metav1.FixInfo) error {
	return nil
}

func (m *MockIKubescape) Patch(ctx context.Context, patchInfo *metav1.PatchInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	return nil, nil
}

func (m *MockIKubescape) ScanImage(ctx context.Context, imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	return nil, nil
}

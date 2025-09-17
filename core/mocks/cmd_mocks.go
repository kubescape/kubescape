package mocks

import (
	"context"

	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
)

type MockIKubescape struct{}

func (m *MockIKubescape) Context() context.Context {
	return context.TODO()
}

func (m *MockIKubescape) Scan(_ *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	return nil, nil
}

func (m *MockIKubescape) List(_ *metav1.ListPolicies) error {
	return nil
}

func (m *MockIKubescape) Download(_ *metav1.DownloadInfo) error {
	return nil
}

func (m *MockIKubescape) SetCachedConfig(_ *metav1.SetConfig) error {
	return nil
}

func (m *MockIKubescape) ViewCachedConfig(_ *metav1.ViewConfig) error {
	return nil
}

func (m *MockIKubescape) DeleteCachedConfig(_ *metav1.DeleteConfig) error {
	return nil
}

func (m *MockIKubescape) Fix(_ *metav1.FixInfo) error {
	return nil
}

func (m *MockIKubescape) Patch(_ *metav1.PatchInfo, _ *cautils.ScanInfo) (bool, error) {
	return false, nil
}

func (m *MockIKubescape) ScanImage(_ *metav1.ImageScanInfo, _ *cautils.ScanInfo) (bool, error) {
	return false, nil
}

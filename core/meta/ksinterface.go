package meta

import (
	"context"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
)

type IKubescape interface {
	Scan(ctx context.Context, scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) // TODO - use scanInfo from v1

	// policies
	List(ctx context.Context, listPolicies *metav1.ListPolicies) error     // TODO - return list response
	Download(ctx context.Context, downloadInfo *metav1.DownloadInfo) error // TODO - return downloaded policies

	// config
	SetCachedConfig(setConfig *metav1.SetConfig) error
	ViewCachedConfig(viewConfig *metav1.ViewConfig) error
	DeleteCachedConfig(ctx context.Context, deleteConfig *metav1.DeleteConfig) error

	// fix
	Fix(ctx context.Context, fixInfo *metav1.FixInfo) error

	// patch
	Patch(ctx context.Context, patchInfo *metav1.PatchInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error)

	// scan image
	ScanImage(ctx context.Context, imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error)
}

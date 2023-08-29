package meta

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling"
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
}

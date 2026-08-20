package meta

import (
	"context"

	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
)

type IKubescape interface {
	Context() context.Context
	SetContext(ctx context.Context)

	Scan(scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) // TODO - use scanInfo from v1

	// ScanContext runs a scan bound to ctx for its complete execution, instead of
	// relying on the receiver's own Context()/SetContext() state. Prefer this over
	// Scan when the caller can hold a *Kubescape across concurrent or overlapping
	// operations, since Scan's context comes from mutable shared state.
	ScanContext(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error)

	// policies
	List(listPolicies *metav1.ListPolicies) (*metav1.ListResult, error)
	Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error)

	// config
	SetCachedConfig(setConfig *metav1.SetConfig) error
	ViewCachedConfig(viewConfig *metav1.ViewConfig) error
	DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error

	// fix
	Fix(fixInfo *metav1.FixInfo) error

	// diff returns the number of new failures at or above the configured severity threshold.
	Diff(diffInfo *metav1.DiffInfo) (int, error)

	// patch
	Patch(patchInfo *metav1.PatchInfo, scanInfo *cautils.ScanInfo) (bool, error)

	// scan image
	ScanImage(imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error)
}

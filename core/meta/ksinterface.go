package meta

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta/cliinterfaces"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling"
)

type IKubescape interface {
	Scan(scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) // TODO - use scanInfo from v1

	// policies
	List(listPolicies *metav1.ListPolicies) error     // TODO - return list response
	Download(downloadInfo *metav1.DownloadInfo) error // TODO - return downloaded policies

	// submit
	Submit(submitInterfaces cliinterfaces.SubmitInterfaces) error            // TODO - func should receive object
	SubmitExceptions(credentials *cautils.Credentials, excPath string) error // TODO - remove

	// config
	SetCachedConfig(setConfig *metav1.SetConfig) error
	ViewCachedConfig(viewConfig *metav1.ViewConfig) error
	DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error

	// delete
	DeleteExceptions(deleteexceptions *metav1.DeleteExceptions) error

	// fix
	Fix(fixInfo *metav1.FixInfo) error
}

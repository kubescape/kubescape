package meta

import (
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/meta/cliinterfaces"
	metav1 "github.com/armosec/kubescape/core/meta/datastructures/v1"
	"github.com/armosec/kubescape/core/pkg/resultshandling"
)

type IKubescape interface {
	Scan(scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) // TODO - use scanInfo from v1

	// policies
	List(listPolicies *metav1.ListPolicies) error     // TODO - return list response
	Download(downloadInfo *metav1.DownloadInfo) error // TODO - return downloaded policies

	// submit
	Submit(submitInterfaces cliinterfaces.SubmitInterfaces) error // TODO - func should receive object
	SubmitExceptions(accountID, excPath string) error             // TODO - remove

	// config
	SetCachedConfig(setConfig *metav1.SetConfig) error
	ViewCachedConfig(viewConfig *metav1.ViewConfig) error
	DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error

	// delete
	DeleteExceptions(deleteexceptions *metav1.DeleteExceptions) error
}

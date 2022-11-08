package resourcehandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"k8s.io/apimachinery/pkg/version"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
)

type IResourceHandler interface {
	GetResources(*cautils.OPASessionObj, *armotypes.PortalDesignator, *cautils.ScanInfo) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, map[string][]registryvulnerabilities.Vulnerability, error)
	GetClusterAPIServerInfo() *version.Info
}

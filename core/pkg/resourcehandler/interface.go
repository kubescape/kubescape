package resourcehandler

import (
	"context"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/opaprocessor"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(context.Context, *cautils.OPASessionObj, *armotypes.PortalDesignator, opaprocessor.IJobProgressNotificationClient) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.KSResources, map[string]bool, error)
	GetClusterAPIServerInfo(ctx context.Context) *version.Info
	GetWorkloadParentKind(workloadinterface.IWorkload) string
}

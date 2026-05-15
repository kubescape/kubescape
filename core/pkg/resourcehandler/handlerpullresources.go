package resourcehandler

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	cloudsupportv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"go.opentelemetry.io/otel"
)

func CollectResources(ctx context.Context, rsrcHandler IResourceHandler, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) error {
	ctx, span := otel.Tracer("").Start(ctx, "resourcehandler.CollectResources")
	defer span.End()
	opaSessionObj.Report.ClusterAPIServerInfo = rsrcHandler.GetClusterAPIServerInfo(ctx)

	// set cloud metadata only when scanning a cluster
	if rsrcHandler.GetCloudProvider() != "" {
		setCloudMetadata(opaSessionObj, rsrcHandler.GetCloudProvider())
	}

	resourcesMap, allResources, externalResources, excludedRulesMap, getErr := rsrcHandler.GetResources(ctx, opaSessionObj, scanInfo)

	// Assign maps and build coverage before returning any error: GetResources
	// mutates opaSessionObj.InfoMap and ResourceToControlsMap even on the
	// all-pulls-failed path, so coverage data is available here regardless of
	// whether getErr is set.
	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.ExternalResources = externalResources
	opaSessionObj.ExcludedRules = excludedRulesMap
	opaSessionObj.ScanCoverage = cautils.BuildScanCoverage(opaSessionObj.InfoMap, opaSessionObj.ResourceToControlsMap)

	if getErr != nil {
		return getErr
	}

	if len(opaSessionObj.K8SResources) == 0 && len(opaSessionObj.ExternalResources) == 0 || len(opaSessionObj.AllResources) == 0 {
		return fmt.Errorf("no resources found to scan")
	}

	return nil
}

func setCloudMetadata(opaSessionObj *cautils.OPASessionObj, provider string) {
	iCloudMetadata := newCloudMetadata(provider)
	if iCloudMetadata == nil {
		return
	}
	cloudMetadata := reportv2.NewCloudMetadata(iCloudMetadata)
	if opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata == nil {
		opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reportv2.ClusterMetadata{}
	}
	opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudMetadata = cloudMetadata
	opaSessionObj.Metadata.ClusterMetadata.CloudMetadata = cloudMetadata             // deprecated - fallback
	opaSessionObj.Report.ClusterCloudProvider = iCloudMetadata.Provider().ToString() // deprecated - fallback

	logger.L().Debug("Cloud metadata", helpers.String("provider", iCloudMetadata.Provider().ToString()), helpers.String("name", iCloudMetadata.GetName()))
}

// getCloudMetadata - get cloud metadata from kubeconfig or API server
// There are 3 options:
// 1. Get cloud provider from API server git version (EKS, GKE)
// 2. Get cloud provider from kubeconfig by parsing the cluster context (EKS, GKE)
// 3. Get cloud provider from kubeconfig by parsing the server URL (AKS)
func newCloudMetadata(provider string) apis.ICloudParser {
	switch provider {
	case cloudsupportv1.AKS:
		return helpersv1.NewAKSMetadata(k8sinterface.GetContextName())
	case cloudsupportv1.EKS:
		return helpersv1.NewEKSMetadata(k8sinterface.GetContextName())
	case cloudsupportv1.GKE:
		return helpersv1.NewGKEMetadata(k8sinterface.GetContextName())
	default:
		return nil
	}
}

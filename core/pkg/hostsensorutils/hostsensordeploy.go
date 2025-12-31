package hostsensorutils

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	// Host data CRD API group and version
	hostDataGroup   = "hostdata.kubescape.cloud"
	hostDataVersion = "v1beta1"
)

// HostSensorHandler is a client that reads host sensor data from Kubernetes CRDs.
//
// The CRDs are created by the node-agent daemonset running on each node.
type HostSensorHandler struct {
	k8sObj        *k8sinterface.KubernetesApi
	dynamicClient dynamic.Interface
}

// NewHostSensorHandler builds a new CRD-based host sensor handler.
func NewHostSensorHandler(k8sObj *k8sinterface.KubernetesApi, _ string) (*HostSensorHandler, error) {
	if k8sObj == nil {
		return nil, fmt.Errorf("nil k8s interface received")
	}
	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil, fmt.Errorf("failed to get k8s config")
	}
	// force GRPC
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// Create dynamic client for CRD access
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	hsh := &HostSensorHandler{
		k8sObj:        k8sObj,
		dynamicClient: dynamicClient,
	}

	// Verify we can access nodes (basic sanity check)
	if nodeList, err := k8sObj.KubernetesClient.CoreV1().Nodes().List(k8sObj.Context, metav1.ListOptions{}); err != nil || len(nodeList.Items) == 0 {
		if err == nil {
			err = fmt.Errorf("no nodes to scan")
		}
		return hsh, fmt.Errorf("in NewHostSensorHandler, failed to get nodes list: %v", err)
	}

	return hsh, nil
}

// Init is a no-op for CRD-based implementation.
// The node-agent daemonset is expected to be already deployed and creating CRDs.
func (hsh *HostSensorHandler) Init(ctx context.Context) error {
	logger.L().Info("Using CRD-based host sensor data collection (no deployment needed)")

	// Verify that at least one CRD type exists
	gvr := schema.GroupVersionResource{
		Group:    hostDataGroup,
		Version:  hostDataVersion,
		Resource: "osreleasefiles",
	}

	list, err := hsh.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		logger.L().Warning("Failed to list OsReleaseFile CRDs - node-agent may not be deployed",
			helpers.Error(err))
		return fmt.Errorf("failed to verify CRD access: %w (ensure node-agent is deployed)", err)
	}

	if len(list.Items) == 0 {
		logger.L().Warning("No OsReleaseFile CRDs found - node-agent may not be running or sensing yet")
	} else {
		logger.L().Info("Successfully verified CRD access", helpers.Int("osReleaseFiles", len(list.Items)))
	}

	return nil
}

// TearDown is a no-op for CRD-based implementation.
// CRDs are managed by the node-agent daemonset lifecycle.
func (hsh *HostSensorHandler) TearDown() error {
	logger.L().Debug("CRD-based host sensor teardown (no-op)")
	return nil
}

// GetNamespace returns empty string as CRDs are cluster-scoped.
func (hsh *HostSensorHandler) GetNamespace() string {
	return ""
}

// listCRDResources is a generic function to list CRD resources and convert them to the expected format.
func (hsh *HostSensorHandler) listCRDResources(ctx context.Context, resourceName, kind string) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{
		Group:    hostDataGroup,
		Version:  hostDataVersion,
		Resource: resourceName,
	}

	logger.L().Debug("Listing CRD resources",
		helpers.String("resource", resourceName),
		helpers.String("kind", kind))

	list, err := hsh.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list %s CRDs: %w", kind, err)
	}

	logger.L().Debug("Retrieved CRD resources",
		helpers.String("kind", kind),
		helpers.Int("count", len(list.Items)))

	return list.Items, nil
}

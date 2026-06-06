package getter

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
	controlInputGroup    = "kubescape.io"
	controlInputVersion  = "v1"
	controlInputResource = "controlinputs"
)

var _ IControlsInputsGetter = &CRDControlInputs{}

// CRDControlInputs retrieves control configuration inputs from the ControlInput CRD in-cluster.
type CRDControlInputs struct {
	client dynamic.Interface
}

// NewCRDControlInputs creates a new CRDControlInputs getter.
// Returns an error if not connected to a cluster or if the dynamic client cannot be created.
func NewCRDControlInputs() (*CRDControlInputs, error) {
	if !k8sinterface.IsConnectedToCluster() {
		return nil, fmt.Errorf("not connected to a Kubernetes cluster")
	}

	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil, fmt.Errorf("failed to get k8s config")
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &CRDControlInputs{
		client: dynamicClient,
	}, nil
}

// GetControlsInputs retrieves control inputs from the ControlInput CRD.
// It looks for a ControlInput resource named "default" in the cluster scope.
func (c *CRDControlInputs) GetControlsInputs(clusterName string) (map[string][]string, error) {
	gvr := schema.GroupVersionResource{
		Group:    controlInputGroup,
		Version:  controlInputVersion,
		Resource: controlInputResource,
	}

	obj, err := c.client.Resource(gvr).Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ControlInput CRD 'default': %w", err)
	}

	return extractControlsInputs(obj)
}

// extractControlsInputs parses the controls map from an unstructured ControlInput object.
func extractControlsInputs(obj *unstructured.Unstructured) (map[string][]string, error) {
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil {
		return nil, fmt.Errorf("failed to parse ControlInput spec: %w", err)
	}
	if !found {
		logger.L().Debug("ControlInput resource has no spec")
		return map[string][]string{}, nil
	}

	controlsRaw, found, err := unstructured.NestedMap(spec, "controls")
	if err != nil {
		return nil, fmt.Errorf("failed to parse ControlInput spec.controls: %w", err)
	}
	if !found {
		logger.L().Debug("ControlInput resource has no spec.controls")
		return map[string][]string{}, nil
	}

	controls := make(map[string][]string, len(controlsRaw))
	for key, val := range controlsRaw {
		arr, ok := val.([]interface{})
		if !ok {
			logger.L().Warning("unexpected type for control input, skipping",
				helpers.String("key", key))
			continue
		}

		strArr := make([]string, 0, len(arr))
		for _, item := range arr {
			strArr = append(strArr, fmt.Sprintf("%v", item))
		}
		controls[key] = strArr
	}

	return controls, nil
}

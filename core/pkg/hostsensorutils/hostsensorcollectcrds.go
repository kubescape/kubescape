package hostsensorutils

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8shostsensor "github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// getCRDResources retrieves resources from CRDs and converts them to HostSensorDataEnvelope format
func (hsh *HostSensorHandler) getCRDResources(ctx context.Context, resourceType k8shostsensor.HostSensorResource) ([]hostsensor.HostSensorDataEnvelope, error) {
	pluralName := k8shostsensor.MapResourceToPlural(resourceType)
	if pluralName == "" {
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	// List CRD resources
	items, err := hsh.listCRDResources(ctx, pluralName, resourceType.String())
	if err != nil {
		return nil, err
	}

	// Convert to HostSensorDataEnvelope format
	result := make([]hostsensor.HostSensorDataEnvelope, 0, len(items))
	for _, item := range items {
		envelope, err := hsh.convertCRDToEnvelope(item, resourceType)
		if err != nil {
			logger.L().Warning("Failed to convert CRD to envelope",
				helpers.String("kind", resourceType.String()),
				helpers.String("name", item.GetName()),
				helpers.Error(err))
			continue
		}
		result = append(result, envelope)
	}

	logger.L().Debug("Retrieved resources from CRDs",
		helpers.String("kind", resourceType.String()),
		helpers.Int("count", len(result)))

	return result, nil
}

// convertCRDToEnvelope converts a CRD unstructured object to HostSensorDataEnvelope
func (hsh *HostSensorHandler) convertCRDToEnvelope(item unstructured.Unstructured, resourceType k8shostsensor.HostSensorResource) (hostsensor.HostSensorDataEnvelope, error) {
	envelope := hostsensor.HostSensorDataEnvelope{}

	// Set API version and kind
	envelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
	envelope.SetKind(resourceType.String())

	// Set name (node name)
	nodeName := item.GetName()
	envelope.SetName(nodeName)

	// Extract content from spec.content
	content, found, err := unstructured.NestedString(item.Object, "spec", "content")
	if err != nil {
		return envelope, fmt.Errorf("failed to extract spec.content: %w", err)
	}
	if !found {
		// fallback to "spec" itself
		content, found, err = unstructured.NestedString(item.Object, "spec")
		if err != nil {
			return envelope, fmt.Errorf("failed to extract spec: %w", err)
		}
		if !found {
			return envelope, fmt.Errorf("spec not found in CRD")
		}
	}

	// Set data as raw bytes
	envelope.SetData([]byte(content))

	return envelope, nil
}

// getOsReleaseFile returns the list of osRelease metadata from CRDs.
func (hsh *HostSensorHandler) getOsReleaseFile(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.OsReleaseFile)
}

// getKernelVersion returns the list of kernelVersion metadata from CRDs.
func (hsh *HostSensorHandler) getKernelVersion(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.KernelVersion)
}

// getLinuxSecurityHardeningStatus returns the list of LinuxSecurityHardeningStatus metadata from CRDs.
func (hsh *HostSensorHandler) getLinuxSecurityHardeningStatus(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.LinuxSecurityHardeningStatus)
}

// getOpenPortsList returns the list of open ports from CRDs.
func (hsh *HostSensorHandler) getOpenPortsList(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.OpenPortsList)
}

// getKernelVariables returns the list of Linux Kernel variables from CRDs.
func (hsh *HostSensorHandler) getKernelVariables(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.LinuxKernelVariables)
}

// getKubeletInfo returns the list of kubelet metadata from CRDs.
func (hsh *HostSensorHandler) getKubeletInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.KubeletInfo)
}

// getKubeProxyInfo returns the list of kubeProxy metadata from CRDs.
func (hsh *HostSensorHandler) getKubeProxyInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.KubeProxyInfo)
}

// getControlPlaneInfo returns the list of controlPlaneInfo metadata from CRDs.
func (hsh *HostSensorHandler) getControlPlaneInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.ControlPlaneInfo)
}

// getCloudProviderInfo returns the list of cloudProviderInfo metadata from CRDs.
func (hsh *HostSensorHandler) getCloudProviderInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.CloudProviderInfo)
}

// getCNIInfo returns the list of CNI metadata from CRDs.
func (hsh *HostSensorHandler) getCNIInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	return hsh.getCRDResources(ctx, k8shostsensor.CNIInfo)
}

// hasCloudProviderInfo iterates over the []hostsensor.HostSensorDataEnvelope list to find info about the cloud provider.
//
// If information are found, then return true. Return false otherwise.
func hasCloudProviderInfo(cpi []hostsensor.HostSensorDataEnvelope) bool {
	for index := range cpi {
		if !reflect.DeepEqual(cpi[index].GetData(), stdjson.RawMessage("{}\\n")) {
			return true
		}
	}

	return false
}

// CollectResources collects all required information from CRDs.
func (hsh *HostSensorHandler) CollectResources(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	infoMap := make(map[string]apis.StatusInfo)

	logger.L().Debug("Collecting host sensor data from CRDs")

	var hasCloudProvider bool
	for _, toPin := range []struct {
		Resource k8shostsensor.HostSensorResource
		Query    func(context.Context) ([]hostsensor.HostSensorDataEnvelope, error)
	}{
		// queries to CRDs
		{
			Resource: k8shostsensor.OsReleaseFile,
			Query:    hsh.getOsReleaseFile,
		},
		{
			Resource: k8shostsensor.KernelVersion,
			Query:    hsh.getKernelVersion,
		},
		{
			Resource: k8shostsensor.LinuxSecurityHardeningStatus,
			Query:    hsh.getLinuxSecurityHardeningStatus,
		},
		{
			Resource: k8shostsensor.OpenPortsList,
			Query:    hsh.getOpenPortsList,
		},
		{
			Resource: k8shostsensor.LinuxKernelVariables,
			Query:    hsh.getKernelVariables,
		},
		{
			Resource: k8shostsensor.KubeletInfo,
			Query:    hsh.getKubeletInfo,
		},
		{
			Resource: k8shostsensor.KubeProxyInfo,
			Query:    hsh.getKubeProxyInfo,
		},
		{
			Resource: k8shostsensor.CloudProviderInfo,
			Query:    hsh.getCloudProviderInfo,
		},
		{
			Resource: k8shostsensor.CNIInfo,
			Query:    hsh.getCNIInfo,
		},
		{
			// ControlPlaneInfo is queried _after_ CloudProviderInfo.
			Resource: k8shostsensor.ControlPlaneInfo,
			Query:    hsh.getControlPlaneInfo,
		},
	} {
		k8sInfo := toPin

		if k8sInfo.Resource == k8shostsensor.ControlPlaneInfo && hasCloudProvider {
			// we retrieve control plane info only if we are not using a cloud provider
			continue
		}

		kcData, err := k8sInfo.Query(ctx)
		if err != nil {
			addInfoToMap(k8sInfo.Resource, infoMap, err)
			logger.L().Ctx(ctx).Warning("Failed to get resource from CRD",
				helpers.String("resource", k8sInfo.Resource.String()),
				helpers.Error(err))
		}

		if k8sInfo.Resource == k8shostsensor.CloudProviderInfo {
			hasCloudProvider = hasCloudProviderInfo(kcData)
		}

		if len(kcData) > 0 {
			res = append(res, kcData...)
		}
	}

	logger.L().Debug("Done collecting information from CRDs", helpers.Int("totalResources", len(res)))
	return res, infoMap, nil
}

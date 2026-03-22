package hostsensorutils

import (
	"context"
	stdjson "encoding/json"
	"fmt"

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
		logger.L().Ctx(ctx).Error("failed to list CRD resources", 
			helpers.String("kind", resourceType.String()),
			helpers.String("plural", pluralName),
			helpers.Error(err))
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

	logger.L().Ctx(ctx).Info("Retrieved resources from CRDs",
		helpers.String("kind", resourceType.String()),
		helpers.Int("count", len(result)))

	return result, nil
}

// convertCRDToEnvelope converts a CRD unstructured object to HostSensorDataEnvelope
func (hsh *HostSensorHandler) convertCRDToEnvelope(item unstructured.Unstructured, resourceType k8shostsensor.HostSensorResource) (hostsensor.HostSensorDataEnvelope, error) {
	envelope := hostsensor.HostSensorDataEnvelope{}

	// Set API version and kind
	// The cluster CRDs use v1beta1, but the OPA policies expect v1beta0.
	// We use hostsensor.Version which is "v1beta0".
	envelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
	envelope.SetKind(resourceType.String())

	// Set name (node name)
	nodeName := item.GetName()
	envelope.SetName(nodeName)

	// The host sensor CRDs store the actual data in the 'spec' field.
	// We need to map 'spec' to the envelope's 'Data' field.
	spec, found, err := unstructured.NestedMap(item.Object, "spec")
	if err != nil {
		return envelope, fmt.Errorf("failed to extract spec: %w", err)
	}
	if !found {
		logger.L().Warning("spec not found in CRD item",
			helpers.String("kind", resourceType.String()),
			helpers.String("name", nodeName))
		return envelope, fmt.Errorf("spec not found in CRD")
	}

	// Remove nodeName as it's already in the envelope metadata
	delete(spec, "nodeName")

	// The Rego policies expect the data in a specific structure.
	// For most resources (like ControlPlaneInfo), the 'spec' already contains the required fields:
	// APIServerInfo, KubeProxyInfo, etc.
	// However, for some resources like KubeletInfo, the CRD's 'spec' wraps the actual data
	// in a field named after the resource type. We need to unwrap it if it exists.
	var data interface{} = spec
	if inner, ok := spec[resourceType.String()]; ok {
		data = inner
	}

	contentBytes, err := stdjson.Marshal(data)
	if err != nil {
		return envelope, fmt.Errorf("failed to marshal spec: %w", err)
	}

	logger.L().Debug("Converted CRD to envelope",
		helpers.String("kind", resourceType.String()),
		helpers.String("name", nodeName),
		helpers.Int("dataSize", len(contentBytes)))

	// Set data as raw bytes
	envelope.SetData(contentBytes)

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
		var data map[string]interface{}
		if err := stdjson.Unmarshal(cpi[index].GetData(), &data); err != nil {
			continue
		}
		if val, ok := data["providerMetaDataAPIAccess"]; ok {
			if b, ok := val.(bool); ok && b {
				return true
			}
		}
	}

	return false
}

// CollectResources collects all required information from CRDs.
func (hsh *HostSensorHandler) CollectResources(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	infoMap := make(map[string]apis.StatusInfo)

	logger.L().Info("Collecting host sensor data from CRDs")

	var hasCloudProvider bool
	// We first query CloudProviderInfo to determine if we should skip ControlPlaneInfo
	cloudProviderData, err := hsh.getCloudProviderInfo(ctx)
	if err != nil {
		addInfoToMap(k8shostsensor.CloudProviderInfo, infoMap, err)
		logger.L().Ctx(ctx).Warning("Failed to get CloudProviderInfo from CRD", helpers.Error(err))
	} else {
		hasCloudProvider = hasCloudProviderInfo(cloudProviderData)
		if len(cloudProviderData) > 0 {
			res = append(res, cloudProviderData...)
		}
	}

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
			Resource: k8shostsensor.CNIInfo,
			Query:    hsh.getCNIInfo,
		},
		{
			Resource: k8shostsensor.ControlPlaneInfo,
			Query:    hsh.getControlPlaneInfo,
		},
	} {
		k8sInfo := toPin

		if k8sInfo.Resource == k8shostsensor.ControlPlaneInfo && hasCloudProvider {
			logger.L().Info("Skipping ControlPlaneInfo collection due to cloud provider presence")
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

		if len(kcData) > 0 {
			res = append(res, kcData...)
		}
	}

	logger.L().Info("Done collecting information from CRDs", helpers.Int("totalResources", len(res)))
	return res, infoMap, nil
}

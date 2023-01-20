package hostsensorutils

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"path"
	"reflect"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"sigs.k8s.io/yaml"
)

// scannerResource is the enumerated type listing all resources from the host-scanner.
type scannerResource string

const (
	// host-scanner resources

	KubeletConfiguration         scannerResource = "KubeletConfiguration"
	OsReleaseFile                scannerResource = "OsReleaseFile"
	KernelVersion                scannerResource = "KernelVersion"
	LinuxSecurityHardeningStatus scannerResource = "LinuxSecurityHardeningStatus"
	OpenPortsList                scannerResource = "OpenPortsList"
	LinuxKernelVariables         scannerResource = "LinuxKernelVariables"
	KubeletCommandLine           scannerResource = "KubeletCommandLine"
	KubeletInfo                  scannerResource = "KubeletInfo"
	KubeProxyInfo                scannerResource = "KubeProxyInfo"
	ControlPlaneInfo             scannerResource = "ControlPlaneInfo"
	CloudProviderInfo            scannerResource = "CloudProviderInfo"
	CNIInfo                      scannerResource = "CNIInfo"
	Version                      scannerResource = "Version"
)

// Path returns the host-scanner route to a resource.
//
// These routes correspond to the host-scanner v1.0.51 image deployed by the host-sensor.yaml file.
//
// See https://github.com/fredbi/host-scanner/blob/6cfe7bd6ee27206e347c40d977df9e6b5ef6c9e3/httphandlers.go#L16
//
// TODO: the next release of the host-scanner exposes routes as lower-case.
func (r scannerResource) Path() string {
	switch r {
	case KubeletConfiguration:
		return "/kubeletConfigurations"
	case OsReleaseFile:
		return "/osRelease"
	case KubeletCommandLine:
		return "/kubeletCommandLine"
	case KernelVersion:
		return "/kernelVersion"
	case LinuxSecurityHardeningStatus:
		return "/linuxSecurityHardening"
	case OpenPortsList:
		return "/openedPorts"
	case LinuxKernelVariables:
		return "/LinuxKernelVariables"
	case KubeletInfo:
		return "/kubeletInfo"
	case KubeProxyInfo:
		return "/kubeProxyInfo"
	case ControlPlaneInfo:
		return "/controlPlaneInfo"
	case CloudProviderInfo:
		return "/cloudProviderInfo"
	case CNIInfo:
		return "/CNIInfo"
	case Version:
		return "/version"
	default:
		panic("dev error: must specify the API path to a scannerResource")
	}
}

func mapHostSensorResourceToApiGroup(r scannerResource) string {
	switch r {
	case
		KubeletConfiguration,
		OsReleaseFile,
		KubeletCommandLine,
		KernelVersion,
		LinuxSecurityHardeningStatus,
		OpenPortsList,
		LinuxKernelVariables,
		KubeletInfo,
		KubeProxyInfo,
		ControlPlaneInfo,
		CloudProviderInfo,
		CNIInfo,
		Version:
		return path.Join(hostsensor.GroupHostSensor, hostsensor.Version)
	default:
		panic("dev error: invalid scannerResource")
	}
}

func (r scannerResource) String() string {
	return string(r)
}

func addInfoToMap(resource scannerResource, infoMap map[string]apis.StatusInfo, err error) {
	group, version := k8sinterface.SplitApiVersion(mapHostSensorResourceToApiGroup(resource))
	r := k8sinterface.JoinResourceTriplets(group, version, resource.String())
	infoMap[r] = apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		InnerInfo:   err.Error(),
	}
}

func reformatKubeletCommandLine(envelope *hostsensor.HostSensorDataEnvelope) {
	// reformat the response about the kubelet command line
	data := map[string]string{
		"fullCommand": string(envelope.GetData()),
	}
	jazon, _ := json.Marshal(data)
	envelope.SetData(jazon)
}

func reformatKubeletConfiguration(envelope *hostsensor.HostSensorDataEnvelope) error {
	// reformat the response about the kubelet configuration, which is provided as YAML
	jazon, err := yaml.YAMLToJSON(envelope.GetData())
	if err != nil {
		return fmt.Errorf("failed to convert kubelet configurations from yaml to json: %w", err)
	}

	envelope.SetData(jazon)

	return nil
}

func reformatVersion(envelope *hostsensor.HostSensorDataEnvelope) {
	// reformat the response about the version of the host-scanner
	version := bytes.Map(versionReplacer, envelope.GetData())
	envelope.SetData(version)
}

func versionReplacer(r rune) rune {
	switch r {
	case '"', '\n':
		return -1
	default:
		return r
	}
}

// hasCloudProviderInfo iterates over the []hostsensor.HostSensorDataEnvelope list to find info about the cloud provider.
//
// If information are found, then return true. Return false otherwise.
//
// TODO: make this check less brittle
func hasCloudProviderInfo(cpi hostsensor.HostSensorDataEnvelope) bool {
	return !reflect.DeepEqual(cpi.GetData(), stdjson.RawMessage("{}\n"))
}

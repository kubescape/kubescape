package hostsensorutils

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"

	"sigs.k8s.io/yaml"
)

// getPodList clones the internal list of pods being watched as a map of pod names.
func (hsh *HostSensorHandler) getPodList() map[string]string {
	hsh.podListLock.RLock()
	res := make(map[string]string, len(hsh.HostSensorPodNames))
	for k, v := range hsh.HostSensorPodNames {
		res[k] = v
	}
	hsh.podListLock.RUnlock()

	return res
}

// HTTPGetToPod send the request to a pod using the HostSensorPort.
func (hsh *HostSensorHandler) HTTPGetToPod(podName, path string) ([]byte, error) {
	restProxy := hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.DaemonSet.Namespace).ProxyGet("http", podName, fmt.Sprintf("%d", hsh.HostSensorPort), path, map[string]string{})
	return restProxy.DoRaw(hsh.k8sObj.Context)
}

func (hsh *HostSensorHandler) getResourcesFromPod(podName, nodeName, resourceKind, path string) (hostsensor.HostSensorDataEnvelope, error) {
	//  send the request and pack the response as an hostSensorDataEnvelope

	resBytes, err := hsh.HTTPGetToPod(podName, path)
	if err != nil {
		return hostsensor.HostSensorDataEnvelope{}, err
	}

	hostSensorDataEnvelope := hostsensor.HostSensorDataEnvelope{}
	hostSensorDataEnvelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
	hostSensorDataEnvelope.SetKind(resourceKind)
	hostSensorDataEnvelope.SetName(nodeName)
	hostSensorDataEnvelope.SetData(resBytes)

	return hostSensorDataEnvelope, nil
}

// ForwardToPod is not currently implemented.
func (hsh *HostSensorHandler) ForwardToPod(podName, path string) ([]byte, error) {
	// NOT IN USE:
	// ---
	// spawn port forwarding
	// req := hsh.k8sObj.KubernetesClient.CoreV1().RESTClient().Post()
	// req = req.Name(podName)
	// req = req.Namespace(hsh.DaemonSet.Namespace)
	// req = req.Resource("pods")
	// req = req.SubResource("portforward")
	// ----
	// https://github.com/gianarb/kube-port-forward
	// fullPath := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward",
	// 	hsh.DaemonSet.Namespace, podName)
	// transport, upgrader, err := spdy.RoundTripperFor(hsh.k8sObj.KubernetesClient.config)
	// if err != nil {
	// 	return nil, err
	// }
	// hostIP := strings.TrimLeft(req.RestConfig.Host, "htps:/")
	// dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, &url.URL{Scheme: "http", Path: path, Host: hostIP})
	return nil, nil
}

// sendAllPodsHTTPGETRequest fills the raw bytes response in the envelope and the node name, but not the GroupVersionKind
// so the caller is responsible to convert the raw data to some structured data and add the GroupVersionKind details
//
// The function produces a worker-pool with a fixed number of workers.
//
// For each node the request is pushed to the jobs channel, the worker sends the request and pushes the result to the result channel.
// When all workers have finished, the function returns a list of results
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(ctx context.Context, path, requestKind string) ([]hostsensor.HostSensorDataEnvelope, error) {
	podList := hsh.getPodList()
	res := make([]hostsensor.HostSensorDataEnvelope, 0, len(podList))
	var wg sync.WaitGroup
	// initialization of the channels
	hsh.workerPool.init(len(podList))

	hsh.workerPool.hostSensorApplyJobs(podList, path, requestKind)
	hsh.workerPool.hostSensorGetResults(&res)
	hsh.workerPool.createWorkerPool(ctx, hsh, &wg)
	hsh.workerPool.waitForDone(&wg)

	return res, nil
}

// GetVersion returns the version of the deployed host scanner.
//
// NOTE: we pick the version from the first responding pod.
func (hsh *HostSensorHandler) GetVersion() (string, error) {
	// loop over pods and port-forward it to each of them
	podList := hsh.getPodList()

	// initialization of the channels
	hsh.workerPool.init(len(podList))
	hsh.workerPool.hostSensorApplyJobs(podList, "/version", "version")
	for job := range hsh.workerPool.jobs {
		resBytes, err := hsh.HTTPGetToPod(job.podName, job.path)
		if err != nil {
			return "", err
		} else {
			version := strings.ReplaceAll(string(resBytes), "\"", "")
			version = strings.ReplaceAll(version, "\n", "")

			return version, nil
		}
	}

	return "", nil
}

// GetKernelVariables returns the list of Linux Kernel variables.
func (hsh *HostSensorHandler) GetKernelVariables(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/LinuxKernelVariables", LinuxKernelVariables)
}

// GetOpenPortsList returns the list of open ports.
func (hsh *HostSensorHandler) GetOpenPortsList(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/openedPorts", OpenPortsList)
}

// GetLinuxSecurityHardeningStatus returns the list of LinuxSecurityHardeningStatus metadata.
func (hsh *HostSensorHandler) GetLinuxSecurityHardeningStatus(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/linuxSecurityHardening", LinuxSecurityHardeningStatus)
}

// GetKubeletInfo returns the list of kubelet metadata.
func (hsh *HostSensorHandler) GetKubeletInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletInfo", KubeletInfo)
}

// GetKubeProxyInfo returns the list of kubeProxy metadata.
func (hsh *HostSensorHandler) GetKubeProxyInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeProxyInfo", KubeProxyInfo)
}

// return list of controlPlaneInfo
func (hsh *HostSensorHandler) GetControlPlaneInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/controlPlaneInfo", ControlPlaneInfo)
}

// GetCloudProviderInfo returns the list of cloudProviderInfo metadata.
func (hsh *HostSensorHandler) GetCloudProviderInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/cloudProviderInfo", CloudProviderInfo)
}

// GetKubeletCommandLine returns the list of kubelet command lines.
func (hsh *HostSensorHandler) GetKubeletCommandLine(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	resps, err := hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletCommandLine", KubeletCommandLine)
	if err != nil {
		return resps, err
	}

	for resp := range resps {
		var data = make(map[string]interface{})
		data["fullCommand"] = string(resps[resp].Data)
		resBytesMarshal, err := json.Marshal(data)
		// TODO catch error
		if err == nil {
			resps[resp].Data = json.RawMessage(resBytesMarshal)
		}
	}

	return resps, nil
}

// GetCNIInfo returns the list of CNI metadata
func (hsh *HostSensorHandler) GetCNIInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/CNIInfo", CNIInfo)
}

// GetKernelVersion returns the list of kernelVersion metadata.
func (hsh *HostSensorHandler) GetKernelVersion(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kernelVersion", "KernelVersion")
}

// GetOsReleaseFile returns the list of osRelease metadata.
func (hsh *HostSensorHandler) GetOsReleaseFile(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/osRelease", "OsReleaseFile")
}

// GetKubeletConfigurations returns the list of kubelet configurations.
func (hsh *HostSensorHandler) GetKubeletConfigurations(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	res, err := hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletConfigurations", "KubeletConfiguration") // empty kind, will be overridden
	for resIdx := range res {
		jsonBytes, ery := yaml.YAMLToJSON(res[resIdx].Data)
		if ery != nil {
			logger.L().Ctx(ctx).Warning("failed to convert kubelet configurations from yaml to json", helpers.Error(ery))
			continue
		}
		res[resIdx].SetData(jsonBytes)
	}

	return res, err
}

// hasCloudProviderInfo iterates over the []hostsensor.HostSensorDataEnvelope list to find info about the cloud provider.
//
// If information are found, then return true. Return false otherwise.
func hasCloudProviderInfo(cpi []hostsensor.HostSensorDataEnvelope) bool {
	for index := range cpi {
		if !reflect.DeepEqual(cpi[index].GetData(), json.RawMessage("{}\n")) {
			return true
		}
	}

	return false
}

// CollectResources collects all required information about all the pods for this host.
func (hsh *HostSensorHandler) CollectResources(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	infoMap := make(map[string]apis.StatusInfo)
	if hsh.DaemonSet == nil {
		return res, nil, nil
	}

	logger.L().Debug("Accessing host scanner")
	version, err := hsh.GetVersion()
	if err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
	}

	if len(version) > 0 {
		logger.L().Info("Host scanner version : " + version)
	} else {
		logger.L().Info("Unknown host scanner version")
	}

	var hasCloudProvider bool
	for _, toPin := range []struct {
		Resource string
		Query    func(context.Context) ([]hostsensor.HostSensorDataEnvelope, error)
	}{
		// queries to the deployed host-scanner
		{
			Resource: KubeletConfiguration,
			Query:    hsh.GetKubeletConfigurations,
		},
		{
			Resource: KubeletCommandLine,
			Query:    hsh.GetKubeletCommandLine,
		},
		{
			Resource: OsReleaseFile,
			Query:    hsh.GetOsReleaseFile,
		},
		{
			Resource: KernelVersion,
			Query:    hsh.GetKernelVersion,
		},
		{
			Resource: LinuxSecurityHardeningStatus,
			Query:    hsh.GetLinuxSecurityHardeningStatus,
		},
		{
			Resource: OpenPortsList,
			Query:    hsh.GetOpenPortsList,
		},
		{
			Resource: LinuxKernelVariables,
			Query:    hsh.GetKernelVariables,
		},
		{
			Resource: KubeletInfo,
			Query:    hsh.GetKubeletInfo,
		},
		{
			Resource: KubeProxyInfo,
			Query:    hsh.GetKubeProxyInfo,
		},
		{
			Resource: CloudProviderInfo,
			Query:    hsh.GetCloudProviderInfo,
		},
		{
			Resource: CNIInfo,
			Query:    hsh.GetCNIInfo,
		},
		{
			// ControlPlaneInfo is queried _after_ CloudProviderInfo.
			Resource: ControlPlaneInfo,
			Query:    hsh.GetControlPlaneInfo,
		},
	} {
		k8sInfo := toPin

		if k8sInfo.Resource == ControlPlaneInfo && hasCloudProvider {
			// we retrieve control plane info only if we are not using a cloud provider
			continue
		}

		kcData, err := k8sInfo.Query(ctx)
		if err != nil {
			addInfoToMap(k8sInfo.Resource, infoMap, err)
			logger.L().Ctx(ctx).Warning(err.Error())
		}

		if k8sInfo.Resource == CloudProviderInfo {
			hasCloudProvider = hasCloudProviderInfo(kcData)
		}

		if len(kcData) > 0 {
			res = append(res, kcData...)
		}
	}

	logger.L().Debug("Done reading information from host scanner")
	return res, infoMap, nil
}

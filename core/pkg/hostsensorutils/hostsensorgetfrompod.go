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

func (hsh *HostSensorHandler) getPodList() (res map[string]string, err error) {
	hsh.podListLock.RLock()
	jsonBytes, err := json.Marshal(hsh.HostSensorPodNames)
	hsh.podListLock.RUnlock()
	if err != nil {
		return res, fmt.Errorf("failed to marshal pod list: %v", err)
	}
	err = json.Unmarshal(jsonBytes, &res)
	if err != nil {
		return res, fmt.Errorf("failed to unmarshal pod list: %v", err)
	}
	return res, nil
}

func (hsh *HostSensorHandler) HTTPGetToPod(podName, path string) ([]byte, error) {
	//  send the request to the port

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

// sendAllPodsHTTPGETRequest fills the raw byte response in the envelope and the node name, but not the GroupVersionKind
// so the caller is responsible to convert the raw data to some structured data and add the GroupVersionKind details
//
// The function produces a worker-pool with a fixed number of workers.
// For each node the request is pushed to the jobs channel, the worker sends the request and pushes the result to the result channel.
// When all workers have finished, the function returns a list of results
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(ctx context.Context, path, requestKind string) ([]hostsensor.HostSensorDataEnvelope, error) {
	podList, err := hsh.getPodList()
	if err != nil {
		return nil, fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}

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

// return host-scanner version
func (hsh *HostSensorHandler) GetVersion() (string, error) {
	// loop over pods and port-forward it to each of them
	podList, err := hsh.getPodList()
	if err != nil {
		return "", fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}

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

// return list of LinuxKernelVariables
func (hsh *HostSensorHandler) GetKernelVariables(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/LinuxKernelVariables", LinuxKernelVariables)
}

// return list of OpenPortsList
func (hsh *HostSensorHandler) GetOpenPortsList(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/openedPorts", OpenPortsList)
}

// return list of LinuxSecurityHardeningStatus
func (hsh *HostSensorHandler) GetLinuxSecurityHardeningStatus(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/linuxSecurityHardening", LinuxSecurityHardeningStatus)
}

// return list of KubeletInfo
func (hsh *HostSensorHandler) GetKubeletInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletInfo", KubeletInfo)
}

// return list of kubeProxyInfo
func (hsh *HostSensorHandler) GetKubeProxyInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeProxyInfo", KubeProxyInfo)
}

// return list of controlPlaneInfo
func (hsh *HostSensorHandler) GetControlPlaneInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/controlPlaneInfo", ControlPlaneInfo)
}

// return list of cloudProviderInfo
func (hsh *HostSensorHandler) GetCloudProviderInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/cloudProviderInfo", CloudProviderInfo)
}

// return list of KubeletCommandLine
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

// return list of CNIInfo
func (hsh *HostSensorHandler) GetCNIInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/CNIInfo", CNIInfo)
}

// return list of kernelVersion
func (hsh *HostSensorHandler) GetKernelVersion(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kernelVersion", "KernelVersion")
}

// return list of osRelease
func (hsh *HostSensorHandler) GetOsReleaseFile(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/osRelease", "OsReleaseFile")
}

// return list of kubeletConfigurations
func (hsh *HostSensorHandler) GetKubeletConfigurations(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	res, err := hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletConfigurations", "KubeletConfiguration") // empty kind, will be overridden
	for resIdx := range res {
		jsonBytes, ery := yaml.YAMLToJSON(res[resIdx].Data)
		if ery != nil {
			logger.L().Ctx(ctx).Error("failed to convert kubelet configurations from yaml to json", helpers.Error(ery))
			continue
		}
		res[resIdx].SetData(jsonBytes)
	}
	return res, err
}

// hasCloudProviderInfo iterate over the []hostsensor.HostSensorDataEnvelope list to find info about cloud provider.
// If information are found, ther return true. Return false otherwise.
func hasCloudProviderInfo(cpi []hostsensor.HostSensorDataEnvelope) bool {
	for index := range cpi {
		if !reflect.DeepEqual(cpi[index].GetData(), json.RawMessage("{}\n")) {
			return true
		}
	}
	return false
}

func (hsh *HostSensorHandler) CollectResources(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	infoMap := make(map[string]apis.StatusInfo)
	if hsh.DaemonSet == nil {
		return res, nil, nil
	}
	var kcData []hostsensor.HostSensorDataEnvelope
	var err error
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
	//
	kcData, err = hsh.GetKubeletConfigurations(ctx)
	if err != nil {
		addInfoToMap(KubeletConfiguration, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetKubeletCommandLine(ctx)
	if err != nil {
		addInfoToMap(KubeletCommandLine, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetOsReleaseFile(ctx)
	if err != nil {
		addInfoToMap(OsReleaseFile, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetKernelVersion(ctx)
	if err != nil {
		addInfoToMap(KernelVersion, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetLinuxSecurityHardeningStatus(ctx)
	if err != nil {
		addInfoToMap(LinuxSecurityHardeningStatus, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetOpenPortsList(ctx)
	if err != nil {
		addInfoToMap(OpenPortsList, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	// GetKernelVariables
	kcData, err = hsh.GetKernelVariables(ctx)
	if err != nil {
		addInfoToMap(LinuxKernelVariables, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetKubeletInfo
	kcData, err = hsh.GetKubeletInfo(ctx)
	if err != nil {
		addInfoToMap(KubeletInfo, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetKubeProxyInfo
	kcData, err = hsh.GetKubeProxyInfo(ctx)
	if err != nil {
		addInfoToMap(KubeProxyInfo, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetCloudProviderInfo
	kcData, err = hsh.GetCloudProviderInfo(ctx)
	isCloudProvider := hasCloudProviderInfo(kcData)
	if err != nil {
		addInfoToMap(CloudProviderInfo, infoMap, err)
		logger.L().Ctx(ctx).Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetControlPlaneInfo
	if !isCloudProvider { // we retrieve control plane info only if we are not using a cloud provider
		kcData, err = hsh.GetControlPlaneInfo(ctx)
		if err != nil {
			addInfoToMap(ControlPlaneInfo, infoMap, err)
			logger.L().Ctx(ctx).Warning(err.Error())
		}
		if len(kcData) > 0 {
			res = append(res, kcData...)
		}
	}

	// GetCNIInfo
	kcData, err = hsh.GetCNIInfo(ctx)
	if err != nil {
		addInfoToMap(CNIInfo, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	logger.L().Debug("Done reading information from host scanner")
	return res, infoMap, nil
}

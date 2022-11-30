package hostsensorutils

import (
	"encoding/json"
	"fmt"
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
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(path, requestKind string) ([]hostsensor.HostSensorDataEnvelope, error) {
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
	hsh.workerPool.createWorkerPool(hsh, &wg)
	hsh.workerPool.waitForDone(&wg)

	return res, nil
}

// return host-scanner version
func (hsh *HostSensorHandler) GetVersion() ([]byte, error) {
	// loop over pods and port-forward it to each of them
	podList, err := hsh.getPodList()
	if err != nil {
		return nil, fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}

	// initialization of the channels
	hsh.workerPool.init(len(podList))
	hsh.workerPool.hostSensorApplyJobs(podList, "/version", "version")
	for job := range hsh.workerPool.jobs {
		resBytes, err := hsh.HTTPGetToPod(job.podName, job.path)
		if err != nil {
			return nil, err
		} else {
			return resBytes, nil
		}
	}
	return nil, nil
}

// return list of LinuxKernelVariables
func (hsh *HostSensorHandler) GetKernelVariables() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/LinuxKernelVariables", "LinuxKernelVariables")
}

// return list of OpenPortsList
func (hsh *HostSensorHandler) GetOpenPortsList() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/openedPorts", "OpenPortsList")
}

// return list of LinuxSecurityHardeningStatus
func (hsh *HostSensorHandler) GetLinuxSecurityHardeningStatus() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/linuxSecurityHardening", "LinuxSecurityHardeningStatus")
}

// return list of KubeletInfo
func (hsh *HostSensorHandler) GetKubeletInfo() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/kubeletInfo", "KubeletInfo")
}

// return list of KubeProxyInfo
func (hsh *HostSensorHandler) GetKubeProxyInfo() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/kubeProxyInfo", "KubeProxyInfo")
}

// return list of KubeProxyInfo
func (hsh *HostSensorHandler) GetControlPlaneInfo() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/controlPlaneInfo", ControlPlaneInfo)
}

// return list of KubeletCommandLine
func (hsh *HostSensorHandler) GetKubeletCommandLine() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	resps, err := hsh.sendAllPodsHTTPGETRequest("/kubeletCommandLine", "KubeletCommandLine")
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

// return list of
func (hsh *HostSensorHandler) GetKernelVersion() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/kernelVersion", "KernelVersion")
}

// return list of
func (hsh *HostSensorHandler) GetOsReleaseFile() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/osRelease", "OsReleaseFile")
}

// return list of
func (hsh *HostSensorHandler) GetKubeletConfigurations() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	res, err := hsh.sendAllPodsHTTPGETRequest("/kubeletConfigurations", "KubeletConfiguration") // empty kind, will be overridden
	for resIdx := range res {
		jsonBytes, err := yaml.YAMLToJSON(res[resIdx].Data)
		if err != nil {
			logger.L().Error("failed to convert kubelet configurations from yaml to json", helpers.Error(err))
			continue
		}
		res[resIdx].SetData(jsonBytes)
	}
	return res, err
}

func (hsh *HostSensorHandler) CollectResources() ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
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
		logger.L().Warning(err.Error())
	}
	if len(version) > 0 {
		versionToPrint := strings.ReplaceAll(string(version), "\"", "")
		versionToPrint = strings.ReplaceAll(versionToPrint, "\n", "")
		logger.L().Info("Host scanner version : " + versionToPrint)
	} else {
		logger.L().Info("Assuming Host scanner version < v1.0.39")
	}
	//
	kcData, err = hsh.GetKubeletConfigurations()
	if err != nil {
		addInfoToMap(KubeletConfiguration, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetKubeletCommandLine()
	if err != nil {
		addInfoToMap(KubeletCommandLine, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetOsReleaseFile()
	if err != nil {
		addInfoToMap(OsReleaseFile, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetKernelVersion()
	if err != nil {
		addInfoToMap(KernelVersion, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetLinuxSecurityHardeningStatus()
	if err != nil {
		addInfoToMap(LinuxSecurityHardeningStatus, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	//
	kcData, err = hsh.GetOpenPortsList()
	if err != nil {
		addInfoToMap(OpenPortsList, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}
	// GetKernelVariables
	kcData, err = hsh.GetKernelVariables()
	if err != nil {
		addInfoToMap(LinuxKernelVariables, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetKubeletInfo
	kcData, err = hsh.GetKubeletInfo()
	if err != nil {
		addInfoToMap(KubeletInfo, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetKubeProxyInfo
	kcData, err = hsh.GetKubeProxyInfo()
	if err != nil {
		addInfoToMap(KubeProxyInfo, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	// GetControlPlaneInfo
	kcData, err = hsh.GetControlPlaneInfo()
	if err != nil {
		addInfoToMap(ControlPlaneInfo, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	logger.L().Debug("Done reading information from host scanner")
	return res, infoMap, nil
}

package hostsensorutils

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/objectsenvelopes/hostsensor"
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
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(path, requestKind string) ([]hostsensor.HostSensorDataEnvelope, error) {
	podList, err := hsh.getPodList()
	if err != nil {
		return nil, fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}
	res := make([]hostsensor.HostSensorDataEnvelope, 0, len(podList))
	resLock := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(len(podList))
	for podName := range podList {
		go func(podName, path string) {
			defer wg.Done()
			resBytes, err := hsh.HTTPGetToPod(podName, path)
			if err != nil {
				fmt.Printf("In sendAllPodsHTTPGETRequest failed to get data '%s' from pod '%s': %v", path, podName, err)
			} else {
				resLock.Lock()
				defer resLock.Unlock()
				hostSensorDataEnvelope := hostsensor.HostSensorDataEnvelope{}
				hostSensorDataEnvelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
				hostSensorDataEnvelope.SetKind(requestKind)
				hostSensorDataEnvelope.SetName(podList[podName])
				hostSensorDataEnvelope.SetData(resBytes)
				res = append(res, hostSensorDataEnvelope)
			}

		}(podName, path)
	}
	wg.Wait()
	return res, nil
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
			fmt.Printf("In GetKubeletConfigurations failed to YAMLToJSON: %v;\n%v", err, res[resIdx])
			continue
		}
		res[resIdx].SetData(jsonBytes)
	}
	return res, err
}

func (hsh *HostSensorHandler) CollectResources() ([]hostsensor.HostSensorDataEnvelope, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	if hsh.DaemonSet == nil {
		return res, nil
	}
	cautils.ProgressTextDisplay("Accessing host sensor")
	cautils.StartSpinner()
	defer cautils.StopSpinner()
	kcData, err := hsh.GetKubeletConfigurations()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	//
	kcData, err = hsh.GetKubeletCommandLine()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	//
	kcData, err = hsh.GetOsReleaseFile()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	//
	kcData, err = hsh.GetKernelVersion()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	//
	kcData, err = hsh.GetLinuxSecurityHardeningStatus()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	//
	kcData, err = hsh.GetOpenPortsList()
	if err != nil {
		return kcData, err
	}
	res = append(res, kcData...)
	// finish
	cautils.SuccessTextDisplay("Read host information from host sensor")
	return res, nil
}

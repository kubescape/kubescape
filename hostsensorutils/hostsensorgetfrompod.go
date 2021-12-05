package hostsensorutils

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/armosec/kubescape/cautils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(path string) ([]HostSensorDataEnvelope, error) {
	podList, err := hsh.getPodList()
	if err != nil {
		return nil, fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}
	res := make([]HostSensorDataEnvelope, 0, len(podList))
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
				res = append(res, HostSensorDataEnvelope{NodeName: podList[podName], Data: resBytes})
			}

		}(podName, path)
	}
	wg.Wait()
	return res, nil
}

// return list of
func (hsh *HostSensorHandler) GetKubeletConfigurations() ([]HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	res, err := hsh.sendAllPodsHTTPGETRequest("/kubeletConfigurations")
	for resIdx := range res {
		jsonBytes, err := yaml.YAMLToJSON(res[resIdx].Data)
		if err != nil {
			fmt.Printf("In GetKubeletConfigurations failed to YAMLToJSON: %v;\n%v", err, res[resIdx])
			continue
		}
		res[resIdx].Data = jsonBytes
		kindDet := metav1.TypeMeta{}
		if err = json.Unmarshal(jsonBytes, &kindDet); err != nil {
			fmt.Printf("In GetKubeletConfigurations failed to Unmarshal GroupVersionKind: %v;\n%v", err, jsonBytes)
			continue
		}
		res[resIdx].GroupVersionResource.Resource = kindDet.Kind
		res[resIdx].GroupVersionResource.Group = kindDet.GroupVersionKind().Group
		res[resIdx].GroupVersionResource.Version = kindDet.GroupVersionKind().Version
	}
	return res, err
}

func (hsh *HostSensorHandler) CollectResources() ([]HostSensorDataEnvelope, error) {
	res := make([]HostSensorDataEnvelope, 0)
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
	cautils.SuccessTextDisplay("Read host information from host sensor")
	return res, nil
}

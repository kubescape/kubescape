package hostsensorutils

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// getPodList clones the internal list of pods being watched as a map of pod names.
func (hsh *HostSensorHandler) getPodList() map[string]string {
	hsh.podListLock.RLock()
	res := make(map[string]string, len(hsh.hostSensorPodNames))
	for k, v := range hsh.hostSensorPodNames {
		res[k] = v
	}
	hsh.podListLock.RUnlock()

	return res
}

// httpGetToPod sends the request to a pod using the HostSensorPort.
func (hsh *HostSensorHandler) httpGetToPod(podName, path string) ([]byte, error) {
	restProxy := hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.daemonSet.Namespace).ProxyGet("http", podName, fmt.Sprintf("%d", hsh.hostSensorPort), path, map[string]string{})
	return restProxy.DoRaw(hsh.k8sObj.Context)
}

func (hsh *HostSensorHandler) getResourcesFromPod(podName, nodeName string, resourceKind scannerResource, path string) (hostsensor.HostSensorDataEnvelope, error) {
	//  send the request and pack the response as an hostSensorDataEnvelope

	resBytes, err := hsh.httpGetToPod(podName, path)
	if err != nil {
		return hostsensor.HostSensorDataEnvelope{}, err
	}

	hostSensorDataEnvelope := hostsensor.HostSensorDataEnvelope{}
	hostSensorDataEnvelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
	hostSensorDataEnvelope.SetKind(resourceKind.String())
	hostSensorDataEnvelope.SetName(nodeName)
	hostSensorDataEnvelope.SetData(resBytes)

	return hostSensorDataEnvelope, nil
}

// forwardToPod is currently not implemented.
func (hsh *HostSensorHandler) forwardToPod(podName, path string) ([]byte, error) {
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
	return nil, errors.New("not implemented")
}

// sendAllPodsHTTPGETRequest fills the raw bytes response in the envelope and the node name, but not the GroupVersionKind
// so the caller is responsible to convert the raw data to some structured data and add the GroupVersionKind details
//
// The function produces a worker-pool with a fixed number of workers.
//
// For each node the request is pushed to the jobs channel, the worker sends the request and pushes the result to the result channel.
// When all workers have finished, the function returns a list of results
func (hsh *HostSensorHandler) sendAllPodsHTTPGETRequest(ctx context.Context, path string, requestKind scannerResource) ([]hostsensor.HostSensorDataEnvelope, error) {
	podList := hsh.getPodList()
	res := make([]hostsensor.HostSensorDataEnvelope, 0, len(podList))
	var wg sync.WaitGroup

	// initialization of the channels
	hsh.workerPool.init(len(podList))

	// log is used to avoid log duplication
	// coming from the different host-scanner instances
	log := NewLogCoupling()

	hsh.workerPool.hostSensorApplyJobs(podList, path, requestKind)
	hsh.workerPool.hostSensorGetResults(&res)
	hsh.workerPool.createWorkerPool(ctx, hsh, &wg, log)
	hsh.workerPool.waitForDone(&wg)

	return res, nil
}

// getVersion returns the version of the deployed host scanner.
//
// NOTE: we pick the version from the first responding pod.
func (hsh *HostSensorHandler) getVersion() (string, error) {
	// loop over pods and port-forward it to each of them
	podList := hsh.getPodList()

	// initialization of the channels
	hsh.workerPool.init(len(podList))
	hsh.workerPool.hostSensorApplyJobs(podList, "/version", "version")
	for job := range hsh.workerPool.jobs {
		resBytes, err := hsh.httpGetToPod(job.podName, job.path)
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

// getKernelVariables returns the list of Linux Kernel variables.
func (hsh *HostSensorHandler) getKernelVariables(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/LinuxKernelVariables", LinuxKernelVariables)
}

// getOpenPortsList returns the list of open ports.
func (hsh *HostSensorHandler) getOpenPortsList(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/openedPorts", OpenPortsList)
}

// getLinuxSecurityHardeningStatus returns the list of LinuxSecurityHardeningStatus metadata.
func (hsh *HostSensorHandler) getLinuxSecurityHardeningStatus(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/linuxSecurityHardening", LinuxSecurityHardeningStatus)
}

// getKubeletInfo returns the list of kubelet metadata.
func (hsh *HostSensorHandler) getKubeletInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeletInfo", KubeletInfo)
}

// getKubeProxyInfo returns the list of kubeProxy metadata.
func (hsh *HostSensorHandler) getKubeProxyInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kubeProxyInfo", KubeProxyInfo)
}

// getControlPlanInfo returns the list of controlPlaneInfo metadata
func (hsh *HostSensorHandler) getControlPlaneInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/controlPlaneInfo", ControlPlaneInfo)
}

// getCloudProviderInfo returns the list of cloudProviderInfo metadata.
func (hsh *HostSensorHandler) getCloudProviderInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/cloudProviderInfo", CloudProviderInfo)
}

// getCNIInfo returns the list of CNI metadata
func (hsh *HostSensorHandler) getCNIInfo(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/CNIInfo", CNIInfo)
}

// getKernelVersion returns the list of kernelVersion metadata.
func (hsh *HostSensorHandler) getKernelVersion(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/kernelVersion", "KernelVersion")
}

// getOsReleaseFile returns the list of osRelease metadata.
func (hsh *HostSensorHandler) getOsReleaseFile(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest(ctx, "/osRelease", "OsReleaseFile")
}

// hasCloudProviderInfo iterates over the []hostsensor.HostSensorDataEnvelope list to find info about the cloud provider.
//
// If information are found, then return true. Return false otherwise.
func hasCloudProviderInfo(cpi []hostsensor.HostSensorDataEnvelope) bool {
	for index := range cpi {
		if !reflect.DeepEqual(cpi[index].GetData(), stdjson.RawMessage("{}\n")) {
			return true
		}
	}

	return false
}

// CollectResources collects all required information about all the pods for this host.
func (hsh *HostSensorHandler) CollectResources(ctx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	res := make([]hostsensor.HostSensorDataEnvelope, 0)
	infoMap := make(map[string]apis.StatusInfo)
	if hsh.daemonSet == nil {
		return res, nil, nil
	}

	logger.L().Debug("Accessing host scanner")
	version, err := hsh.getVersion()
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
		Resource scannerResource
		Query    func(context.Context) ([]hostsensor.HostSensorDataEnvelope, error)
	}{
		// queries to the deployed host-scanner
		{
			Resource: OsReleaseFile,
			Query:    hsh.getOsReleaseFile,
		},
		{
			Resource: KernelVersion,
			Query:    hsh.getKernelVersion,
		},
		{
			Resource: LinuxSecurityHardeningStatus,
			Query:    hsh.getLinuxSecurityHardeningStatus,
		},
		{
			Resource: OpenPortsList,
			Query:    hsh.getOpenPortsList,
		},
		{
			Resource: LinuxKernelVariables,
			Query:    hsh.getKernelVariables,
		},
		{
			Resource: KubeletInfo,
			Query:    hsh.getKubeletInfo,
		},
		{
			Resource: KubeProxyInfo,
			Query:    hsh.getKubeProxyInfo,
		},
		{
			Resource: CloudProviderInfo,
			Query:    hsh.getCloudProviderInfo,
		},
		{
			Resource: CNIInfo,
			Query:    hsh.getCNIInfo,
		},
		{
			// ControlPlaneInfo is queried _after_ CloudProviderInfo.
			Resource: ControlPlaneInfo,
			Query:    hsh.getControlPlaneInfo,
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

package hostsensorutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

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
func (hsh *HostSensorHandler) GetVersion() (string, error) {
	// loop over pods and port-forward it to each of them
	podList, err := hsh.getPodList()
	if err != nil {
		return "", fmt.Errorf("in GetVersion, failed to getPodList: %v", err)
	}

	// initialization of the channels
	hsh.workerPool.init(len(podList))
	hsh.workerPool.hostSensorApplyJobs(podList, "/version", "version")
	for job := range hsh.workerPool.jobs {
		resBytes, err := hsh.HTTPGetToPod(job.podName, job.path)
		if err != nil {
			logger.L().Debug(err.Error())
		} else {
			version := strings.ReplaceAll(string(resBytes), "\"", "")
			version = strings.ReplaceAll(version, "\n", "")
			return version, nil
		}
	}
	return "", nil
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

// return list of KubeProxyInfo
func (hsh *HostSensorHandler) GetCloudProviderInfo() ([]hostsensor.HostSensorDataEnvelope, error) {
	// loop over pods and port-forward it to each of them
	return hsh.sendAllPodsHTTPGETRequest("/cloudProviderInfo", CloudProviderInfo)
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
		jsonBytes, ery := yaml.YAMLToJSON(res[resIdx].Data)
		if ery != nil {
			logger.L().Error("failed to convert kubelet configurations from yaml to json", helpers.Error(ery))
			continue
		}
		res[resIdx].SetData(jsonBytes)
	}
	return res, err
}

// return host-scanner version
func (hsh *HostSensorHandler) TestPortForwarding(buff *strings.Builder) (string, error) {
	// loop over pods and port-forward it to each of them
	podList, err := hsh.getPodList()
	if err != nil {
		return "", fmt.Errorf("failed to sendAllPodsHTTPGETRequest: %v", err)
	}

	// initialization of the channels
	hsh.workerPool.init(len(podList))
	hsh.workerPool.hostSensorApplyJobs(podList, "/version", "version")
	for job := range hsh.workerPool.jobs {
		buff.WriteString("POST /test/demo_form.php HTTP/1.1\r\n")
		resBytes, err := hsh.HTTPGetToPod(job.podName, job.path)
		if err != nil {
			logger.L().Debug(err.Error())
		} else {
			version := strings.ReplaceAll(string(resBytes), "\"", "")
			version = strings.ReplaceAll(version, "\n", "")
			return version, nil
		}
	}
	return "", nil
}

func (hsh *HostSensorHandler) CollectResources() ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	podList, err := hsh.getPodList()
	if err != nil {
		logger.L().Debug("In CollectResources error getting podslist, err:" + err.Error())
	}
	for podName := range podList {
		pr, err := NewPortForwarder(hsh.GetNamespace(), podName, int(hsh.HostSensorPort))
		if err != nil {
			logger.L().Warning(err.Error())
		}
		err = pr.ForwardPorts()
		if err != nil {
			logger.L().Warning(err.Error())
		}
		test, err := hsh.TestPortForwarding(pr.port.Local)
		pr.port.ReadyPort <- true
		// wait for interrupt or conn closure
		select {
		case <-pr.stopChan:
		case <-pr.streamConn.CloseChan():
			runtime.HandleError(errors.New("lost connection to pod"))
		}
		fmt.Printf("test: %s", test)
	}
	return hsh.GetHostSensorDataEnveloped()
}

func (hsh *HostSensorHandler) GetHostSensorDataEnveloped() ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
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
		logger.L().Info("Host scanner version : " + version)
	} else {
		logger.L().Info("Unknown host scanner version")
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

	// GetCloudProviderInfo
	kcData, err = hsh.GetCloudProviderInfo()
	if err != nil {
		addInfoToMap(CloudProviderInfo, infoMap, err)
		logger.L().Warning(err.Error())
	}
	if len(kcData) > 0 {
		res = append(res, kcData...)
	}

	logger.L().Debug("Done reading information from host scanner")
	return res, infoMap, nil
}

// =====================

func NewPortForwarder(namespace, podName string, port int) (*PortForwarder, error) {
	fmt.Print("NewPortForwarder")
	// var config *rest.Config
	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil, errors.New("failed to create new PortForwarder, config is nil")
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, podName)
	hostIP := strings.TrimLeft(config.Host, "https:/")

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}
	// stopCh control the port forwarding lifecycle. When it gets closed the
	// port forward will terminate
	stopCh := make(chan struct{}, 1)
	// readyCh communicate when the port forward is ready to get traffic
	readyCh := make(chan struct{})

	stream := genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, &url.URL{Scheme: "https", Path: path, Host: hostIP})
	if dialer == nil {
		return nil, errors.New("failed to create new PortForwarder, dialer is nil")
	}
	_, err = portforward.New(dialer, []string{fmt.Sprintf("%d", port)}, stopCh, readyCh, stream.Out, stream.ErrOut)
	if err != nil {
		return nil, err
	}
	streamConn, _, err := dialer.Dial(PortForwardProtocolV1Name)
	if err != nil {
		return nil, err
	}
	localBuff := &strings.Builder{}
	localBuff.Grow(5000)
	forwardedPort := ForwardedPort{ReadyPort: make(chan bool), Local: localBuff, Remote: port}

	// fw, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", req.LocalPort, req.PodPort)}, req.StopCh, req.ReadyCh, req.Streams.Out, req.Streams.ErrOut)

	return &PortForwarder{
		dialer: dialer,
		// addresses: parsedAddresses,
		port:       forwardedPort,
		streamConn: streamConn,
		stopChan:   stopCh,
		Ready:      readyCh,
		// requestID:  0,
		// out:       out,
		// errOut:    errOut,
		// listeners  []io.Closer
	}, nil
}

// PortForwarder knows how to listen for local connections and forward them to
// a remote pod via an upgraded HTTP request.
const PortForwardProtocolV1Name = "portforward.k8s.io"

// type PortForwarder struct {
// 	// addresses []listenAddress
// 	// ports    []ForwardedPort
// 	stopChan <-chan struct{}

// 	dialer        httpstream.Dialer
// 	streamConn    httpstream.Connection
// 	listeners     []io.Closer
// 	Ready         chan struct{}
// 	requestIDLock sync.Mutex
// 	requestID     int
// 	out           io.Writer
// 	errOut        io.Writer
// }

// // handleConnection copies data between the local connection and the stream to
// // the remote server.
// func (pf *PortForwarder) handleConnection(port int) error {
// 	// defer conn.Close()
// 	var err error
// 	buff := &strings.Builder{}
// 	buff.WriteString("POST /test/demo_form.php HTTP/1.1\r\n")
// 	resBuff := &strings.Builder{}
// 	resBuff.Grow(5000)

// 	// POST /test/demo_form.php HTTP/1.1
// 	// Host: w3schools.com

// 	// name1=value1&name2=value2

// 	defer pf.streamConn.Close()
// 	if pf.out != nil {
// 		logger.L().Debug("Handling connection for", helpers.Int("port", port))
// 		// fmt.Fprintf(pf.out, "Handling connection for %d\n", port.Local)
// 	}

// 	// requestID := pf.nextRequestID()

// 	// create error stream
// 	headers := http.Header{}
// 	headers.Set(v1.StreamType, v1.StreamTypeError)
// 	headers.Set(v1.PortHeader, fmt.Sprintf("%d", port))
// 	headers.Set(v1.PortForwardRequestIDHeader, strconv.Itoa(pf.requestID))
// 	errorStream, err := pf.streamConn.CreateStream(headers)
// 	if err != nil {
// 		errmsg := fmt.Errorf("error creating error stream for port %d: %v", port, err)
// 		runtime.HandleError(errmsg)
// 		return errmsg
// 	}
// 	// we're not writing to this stream
// 	errorStream.Close()

// 	errorChan := make(chan error)
// 	go func() {
// 		message, err := ioutil.ReadAll(errorStream)
// 		switch {
// 		case err != nil:
// 			errorChan <- fmt.Errorf("error reading from error stream for port %d: %v", port, err)
// 		case len(message) > 0:
// 			errorChan <- fmt.Errorf("an error occurred forwarding %d: %v", port, string(message))
// 		}
// 		close(errorChan)
// 	}()

// 	// create data stream
// 	headers.Set(v1.StreamType, v1.StreamTypeData)
// 	dataStream, err := pf.streamConn.CreateStream(headers)
// 	if err != nil {
// 		errmsg := fmt.Errorf("error creating forwarding stream for port %d: %v", port, err)
// 		runtime.HandleError(errmsg)
// 		return errmsg
// 	}

// 	localError := make(chan struct{})
// 	remoteDone := make(chan struct{})

// 	go func() {

// 		// Copy from the remote side to the local port.
// 		if data, err := io.Copy(os.Stdout, dataStream); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
// 			runtime.HandleError(fmt.Errorf("error copying from remote stream to local connection: %v", err))
// 		} else {
// 			fmt.Print(data)
// 		}

// 		// inform the select below that the remote copy is done
// 		close(remoteDone)
// 	}()

// 	go func() {

// 		<-pf.Ready

// 		// inform server we're not sending any more data after copy unblocks
// 		defer dataStream.Close()

// 		// Copy from the local port to the remote side.
// 		if data, err := io.Copy(dataStream, strings.NewReader(buff.String())); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
// 			runtime.HandleError(fmt.Errorf("error copying from local connection to remote stream: %v", err))
// 			// break out of the select below without waiting for the other copy to finish
// 			close(localError)
// 		} else {
// 			fmt.Print(data)
// 		}
// 	}()

// 	// wait for either a local->remote error or for copying from remote->local to finish
// 	select {
// 	case <-remoteDone:
// 	case <-localError:
// 	}

// 	// always expect something on errorChan (it may be nil)
// 	err = <-errorChan
// 	if err != nil {
// 		runtime.HandleError(err)
// 		pf.streamConn.Close()
// 	}
// 	return nil
// }

// ============================

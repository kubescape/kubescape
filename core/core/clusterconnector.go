package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	operatorServicePort string = "4002"
	operatorTriggerPath string = "v1/triggerAction"
	kubescapeNamespace  string = "kubescape"
)

type OperatorAdapter struct {
	httpPostFunc func(httputils.IHttpClient, string, map[string]string, []byte) (*http.Response, error)
	cautils.OperatorScanInfo
	cautils.OperatorConnector
}

var errOperatorNotFound = errors.New("could not find the Kubescape Operator chart, please validate that the Kubescape Operator helm chart is installed and running -> https://github.com/kubescape/helm-charts")

func getOperatorPod(k8sClient *k8sinterface.KubernetesApi, ns string) (*v1.Pod, error) {
	if k8sClient == nil || k8sClient.KubernetesClient == nil {
		return nil, errors.New("kubernetes client is not initialised")
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "app=operator",
	}
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods(ns).List(k8sClient.Context, listOptions)
	if err != nil {
		return nil, err
	}

	if len(pods.Items) == 0 {
		return nil, errOperatorNotFound
	}

	// More than one operator pod can be present during HA deployments or
	// rolling upgrades. The operator has no leader election, so any ready
	// replica can serve v1/triggerAction: picking the first ready pod is a
	// deliberate choice, not an approximation. A single pod goes through the
	// same check, so a not-yet-ready lone pod is reported instead of being
	// handed to CreatePortForwarder.
	for i := range pods.Items {
		if isPodReady(&pods.Items[i]) {
			return &pods.Items[i], nil
		}
	}
	return nil, fmt.Errorf("found %d Kubescape Operator pod(s) in namespace %q, but none are running and ready", len(pods.Items), ns)
}

func isPodReady(pod *v1.Pod) bool {
	if pod.DeletionTimestamp != nil {
		// A terminating pod keeps reporting Ready=True for the whole
		// termination grace period, so it must not be selected.
		return false
	}
	if pod.Status.Phase != v1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == v1.PodReady {
			return condition.Status == v1.ConditionTrue
		}
	}
	return false
}

func NewOperatorAdapter(scanInfo cautils.OperatorScanInfo, ns string) (*OperatorAdapter, error) {
	k8sClient := getKubernetesApi()
	if k8sClient == nil || k8sClient.KubernetesClient == nil {
		return nil, errors.New("could not connect to cluster: set --kubeconfig, $KUBECONFIG, or $KUBERNETES_MASTER")
	}
	pod, err := getOperatorPod(k8sClient, ns)
	if err != nil {
		return nil, err
	}
	operatorConnector, err := cautils.CreatePortForwarder(k8sClient, pod, operatorServicePort, ns)
	if err != nil {
		return nil, err
	}

	return &OperatorAdapter{
		httpPostFunc:      httputils.HttpPost,
		OperatorScanInfo:  scanInfo,
		OperatorConnector: operatorConnector,
	}, nil
}

func (a *OperatorAdapter) httpPostOperatorScanRequest(body apis.Commands) (string, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("in 'httpPostOperatorScanRequest' failed to json.Marshal, reason: %w", err)
	}

	err = a.StartPortForwarder()
	if err != nil {
		a.StopPortForwarder()
		return "", err
	}
	defer a.StopPortForwarder()

	urlQuery := url.URL{
		Scheme: "http",
		Host:   a.GetPortForwardLocalhost(),
		Path:   operatorTriggerPath,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := a.httpPostFunc(client, urlQuery.String(), map[string]string{"Content-Type": "application/json"}, reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http-error: %d", resp.StatusCode)
	}
	return "success", nil
}

func (a *OperatorAdapter) OperatorScan() (string, error) {
	payload := a.GetRequestPayload()
	if err := a.ValidatePayload(payload); err != nil {
		return "", err
	}
	res, err := a.httpPostOperatorScanRequest(*payload)
	if err != nil {
		return "", err
	}
	return res, nil
}

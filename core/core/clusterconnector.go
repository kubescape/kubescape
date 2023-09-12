package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	operatorServicePort string = "4002"
	operatorTriggerPath string = "v1/triggerAction"
	KubescapeScanV1     string = "scanV1"
	kubescapeNamespace  string = "kubescape"
)

type OperatorAdapter struct {
	clusterName  string
	httpPostFunc func(httputils.IHttpClient, string, map[string]string, []byte) (*http.Response, error)
	cautils.OperatorConnector
}

func getOperatorPod(k8sClient *k8sinterface.KubernetesApi) (*v1.Pod, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=operator",
	}
	pods, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).List(k8sClient.Context, listOptions)
	if err != nil {
		return nil, err
	}
	if len(pods.Items) != 1 {
		return nil, errors.New("in 'getOperatorPod' can't find specific operator pod")
	}

	return &pods.Items[0], nil
}

func NewOperatorAdapter() (*OperatorAdapter, error) {
	k8sClient := getKubernetesApi()
	pod, err := getOperatorPod(k8sClient)
	if err != nil {
		return nil, err
	}

	operatorConnector, err := cautils.CreatePortForwarder(k8sClient, pod, operatorServicePort, kubescapeNamespace)
	if err != nil {
		return nil, err
	}
	return &OperatorAdapter{
		clusterName:       k8sinterface.GetContextName(),
		httpPostFunc:      httputils.HttpPost,
		OperatorConnector: operatorConnector,
	}, nil
}

func (a *OperatorAdapter) httpPostOperatorScanRequest(body apis.Commands) (string, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("in 'httpPostOperatorScanRequest' failed to json.Marshal, reason: %v", err)
	}

	err = a.StartPortForwarder()
	if err != nil {
		return "", err
	}
	defer a.StopPortForwarder()

	urlQuery := url.URL{
		Scheme: "http",
		Host:   a.GetPortForwardLocalhost(),
		Path:   operatorTriggerPath,
	}

	resp, err := a.httpPostFunc(http.DefaultClient, urlQuery.String(), map[string]string{"Content-Type": "application/json"}, reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return httputils.HttpRespToString(resp)
}

func buildVulnerabilityScanCommand(clusterName, namespace string) *apis.Command {
	wildWlid := wlid.GetWLID(clusterName, namespace, "", "")
	return &apis.Command{
		CommandName: apis.TypeScanImages,
		WildWlid:    wildWlid,
	}
}

func buildConfigScanCommand(operatorInfo cautils.OperatorInfo) *apis.Command {
	return &apis.Command{
		CommandName: apis.TypeRunKubescape,
		Args: map[string]interface{}{
			KubescapeScanV1: utilsmetav1.PostScanRequest{
				Submit:             &operatorInfo.ConfigScanInfo.Submit,
				ExcludedNamespaces: operatorInfo.ConfigScanInfo.ExcludedNamespaces,
				IncludeNamespaces:  operatorInfo.ConfigScanInfo.IncludedNamespaces,
				TargetType:         apisv1.KindFramework,
				TargetNames:        operatorInfo.Frameworks,
				HostScanner:        &operatorInfo.HostScanner,
			},
		},
	}
}

func convertToOperatorTriggerInfo(clusterName string, operatorInfo cautils.OperatorInfo) (*apis.Commands, error) {
	triggerInfo := apis.Commands{}

	if operatorInfo.OperatorServicesStatus.ScanVulnerabilities {
		if len(operatorInfo.VulnerabilitiesScanInfo.IncludeNamespaces) == 0 {
			triggerInfo.Commands = append(triggerInfo.Commands, *buildVulnerabilityScanCommand(clusterName, ""))
		} else {
			for _, namespace := range operatorInfo.VulnerabilitiesScanInfo.IncludeNamespaces {
				triggerInfo.Commands = append(triggerInfo.Commands, *buildVulnerabilityScanCommand(clusterName, namespace))
			}
		}
	} else if operatorInfo.OperatorServicesStatus.ScanConfig {
		triggerInfo.Commands = append(triggerInfo.Commands, *buildConfigScanCommand(operatorInfo))
	} else {
		// should never happened
		return nil, errors.New("HandleScanRequest: operator service not exist")
	}

	return &triggerInfo, nil
}

func (a *OperatorAdapter) OperatorScan(operatorInfo cautils.OperatorInfo) (string, error) {
	commands, err := convertToOperatorTriggerInfo(a.clusterName, operatorInfo)
	if err != nil {
		return "", err
	}

	res, err := a.httpPostOperatorScanRequest(*commands)
	if err != nil {
		return "", err
	}
	return res, nil
}

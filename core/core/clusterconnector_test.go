package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_getOperatorPod(t *testing.T) {
	testCases := []struct {
		name                                  string
		createOperatorPod                     bool
		createAnotherOperatorPodWithSameLabel bool
		expectedError                         error
	}{
		{
			name:                                  "test error no operator exist",
			createOperatorPod:                     false,
			createAnotherOperatorPodWithSameLabel: false,
			expectedError:                         fmt.Errorf("in 'getOperatorPod' can't find specific operator pod"),
		},
		{
			name:                                  "test error several operators exist",
			createOperatorPod:                     true,
			createAnotherOperatorPodWithSameLabel: true,
			expectedError:                         fmt.Errorf("in 'getOperatorPod' can't find specific operator pod"),
		},
		{
			name:                                  "test no error",
			createOperatorPod:                     true,
			createAnotherOperatorPodWithSameLabel: false,
			expectedError:                         nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewSimpleClientset(),
				Context:          context.TODO(),
			}

			var createdOperatorPod *v1.Pod
			if tc.createOperatorPod {
				operatorPod := v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "first",
						Labels: map[string]string{
							"app": "operator",
						},
					},
				}
				var err error
				createdOperatorPod, err = k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
				assert.Equal(t, nil, err)
			}
			if tc.createAnotherOperatorPodWithSameLabel {
				operatorPod := v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "second",
						Labels: map[string]string{
							"app": "operator",
						},
					},
				}
				_, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
				assert.Equal(t, nil, err)
			}

			pod, err := getOperatorPod(&k8sClient)
			assert.Equal(t, err, tc.expectedError)
			if tc.expectedError == nil {
				assert.Equal(t, pod, createdOperatorPod)
			}
		})
	}
}

func Test_buildVulnerabilityScanCommand(t *testing.T) {
	testCases := []struct {
		name        string
		clusterName string
		namespace   string
		result      *apis.Command
	}{
		{
			name:        "happy case",
			clusterName: "any",
			namespace:   "many",
			result: &apis.Command{
				CommandName: apis.TypeScanImages,
				WildWlid:    "wlid://cluster-any/namespace-many",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildVulnerabilityScanCommand(tc.clusterName, tc.namespace)
			assert.Equal(t, tc.result, result)
		})
	}
}

func newTrue() *bool {
	t := true
	return &t
}

func newFalse() *bool {
	f := false
	return &f
}

func Test_buildConfigScanCommand(t *testing.T) {
	testCases := []struct {
		name         string
		clusterName  string
		operatorInfo cautils.OperatorInfo
		result       *apis.Command
	}{
		{
			name:        "happy case",
			clusterName: "any",
			operatorInfo: cautils.OperatorInfo{
				ConfigScanInfo: cautils.ConfigScanInfo{
					Submit:             false,
					ExcludedNamespaces: []string{"1111"},
					IncludedNamespaces: []string{"2222"},
					HostScanner:        false,
					Frameworks:         []string{"any", "many"},
				},
			},
			result: &apis.Command{
				CommandName: apis.TypeRunKubescape,
				Args: map[string]interface{}{
					KubescapeScanV1: utilsmetav1.PostScanRequest{
						Submit:             newFalse(),
						ExcludedNamespaces: []string{"1111"},
						IncludeNamespaces:  []string{"2222"},
						TargetType:         apisv1.KindFramework,
						TargetNames:        []string{"any", "many"},
						HostScanner:        newFalse(),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildConfigScanCommand(tc.operatorInfo)
			assert.Equal(t, tc.result, result)
		})
	}
}

func Test_convertToOperatorTriggerInfo(t *testing.T) {
	testCases := []struct {
		name          string
		clusterName   string
		operatorInfo  cautils.OperatorInfo
		result        *apis.Commands
		expectedError error
	}{
		{
			name:          "scan kubescape config",
			clusterName:   "any",
			expectedError: nil,
			operatorInfo: cautils.OperatorInfo{
				OperatorServicesStatus: cautils.OperatorServicesStatus{
					ScanConfig:          true,
					ScanVulnerabilities: false,
				},
				ConfigScanInfo: cautils.ConfigScanInfo{
					Submit:             false,
					ExcludedNamespaces: []string{"1111"},
					IncludedNamespaces: []string{"2222"},
					HostScanner:        false,
					Frameworks:         []string{"any", "many"},
				},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					apis.Command{
						CommandName: apis.TypeRunKubescape,
						Args: map[string]interface{}{
							KubescapeScanV1: utilsmetav1.PostScanRequest{
								Submit:             newFalse(),
								ExcludedNamespaces: []string{"1111"},
								IncludeNamespaces:  []string{"2222"},
								TargetType:         apisv1.KindFramework,
								TargetNames:        []string{"any", "many"},
								HostScanner:        newFalse(),
							},
						},
					},
				},
			},
		},
		{
			name:          "scan kubescape vulns",
			clusterName:   "any",
			expectedError: nil,
			operatorInfo: cautils.OperatorInfo{
				OperatorServicesStatus: cautils.OperatorServicesStatus{
					ScanConfig:          false,
					ScanVulnerabilities: true,
				},
				VulnerabilitiesScanInfo: cautils.VulnerabilitiesScanInfo{
					IncludeNamespaces: []string{""},
				},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					apis.Command{
						CommandName: apis.TypeScanImages,
						WildWlid:    "wlid://cluster-any",
					},
				},
			},
		},
		{
			name:          "error",
			clusterName:   "any",
			expectedError: errors.New("HandleScanRequest: operator service not exist"),
			operatorInfo: cautils.OperatorInfo{
				OperatorServicesStatus: cautils.OperatorServicesStatus{
					ScanConfig:          false,
					ScanVulnerabilities: false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := convertToOperatorTriggerInfo(tc.clusterName, tc.operatorInfo)
			assert.Equal(t, tc.expectedError, err)
			if result != nil {
				assert.Equal(t, tc.result, result)
			}
		})
	}
}

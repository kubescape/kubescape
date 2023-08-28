package resourcehandler

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	//go:embed testdata/kubeconfig_mock.json
	kubeConfigMock string
)

func getKubeConfigMock() *clientcmdapi.Config {
	kubeConfig := clientcmdapi.Config{}
	if err := json.Unmarshal([]byte(kubeConfigMock), &kubeConfig); err != nil {
		panic(err)
	}
	return &kubeConfig
}
func Test_getCloudMetadata(t *testing.T) {
	type args struct {
		opaSessionObj *cautils.OPASessionObj
		kubeConfig    *clientcmdapi.Config
		context       string
	}
	kubeConfig := getKubeConfigMock()
	tests := []struct {
		want apis.ICloudParser
		args args
		name string
	}{
		{
			name: "Test_getCloudMetadata - GitVersion: GKE",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reportv2.PostureReport{
						ClusterAPIServerInfo: &version.Info{
							GitVersion: "v1.25.4-gke.1600",
						},
					},
				},
				context:    "",
				kubeConfig: kubeConfig,
			},
			want: helpersv1.NewGKEMetadata(""),
		},
		{
			name: "Test_getCloudMetadata_context_EKS",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reportv2.PostureReport{
						ClusterAPIServerInfo: &version.Info{
							GitVersion: "v1.25.4-eks.1600",
						},
					},
				},
				kubeConfig: kubeConfig,
				context:    "arn:aws:eks:eu-west-1:xxx:cluster/xxxx",
			},
			want: helpersv1.NewEKSMetadata(""),
		},
		{
			name: "Test_getCloudMetadata_context_AKS",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reportv2.PostureReport{
						ClusterAPIServerInfo: &version.Info{
							GitVersion: "v1",
						},
					},
				},
				kubeConfig: kubeConfig,
				context:    "xxxx-2",
			},
			want: helpersv1.NewAKSMetadata(""),
		},
	}
	k8sinterface.K8SConfig = &rest.Config{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sinterface.SetClusterContextName(tt.args.context)
			k8sinterface.SetClientConfigAPI(tt.args.kubeConfig)
			k8sinterface.SetK8SGitServerVersion(tt.args.opaSessionObj.Report.ClusterAPIServerInfo.GitVersion)
			k8sinterface.SetConnectedToCluster(true)

			got := getCloudMetadata(tt.args.opaSessionObj)
			if got == nil {
				t.Errorf("getCloudMetadata() = %v, want %v", got, tt.want.Provider())
				return
			}
			if got.Provider() != tt.want.Provider() {
				t.Errorf("getCloudMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(nil)
}

// https://github.com/kubescape/kubescape/pull/1004
// Cluster named .*eks.* config without a cloudconfig panics whereas we just want to scan a file
func getResourceHandlerMock() *K8sResourceHandler {
	client := fakeclientset.NewSimpleClientset()
	fakeDiscovery := client.Discovery()

	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DynamicClient:    fake.NewSimpleDynamicClient(runtime.NewScheme()),
		DiscoveryClient:  fakeDiscovery,
		Context:          context.Background(),
	}

	return NewK8sResourceHandler(k8s, nil, nil, "test")
}
func Test_CollectResources(t *testing.T) {
	resourceHandler := getResourceHandlerMock()
	objSession := &cautils.OPASessionObj{
		Metadata: &reportv2.Metadata{
			ScanMetadata: reportv2.ScanMetadata{
				ScanningTarget: reportv2.Cluster,
			},
		},
		Report: &reportv2.PostureReport{
			ClusterAPIServerInfo: nil,
		},
	}

	assert.NotPanics(t, func() {
		CollectResources(context.TODO(), resourceHandler, []cautils.PolicyIdentifier{}, objSession, cautils.NewProgressHandler(""), &cautils.ScanInfo{})
	}, "Cluster named .*eks.* without a cloud config panics on cluster scan !")

	assert.NotPanics(t, func() {
		objSession.Metadata.ScanMetadata.ScanningTarget = reportv2.File
		CollectResources(context.TODO(), resourceHandler, []cautils.PolicyIdentifier{}, objSession, cautils.NewProgressHandler(""), &cautils.ScanInfo{})
	}, "Cluster named .*eks.* without a cloud config panics on non-cluster scan !")

}

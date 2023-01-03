package policyhandler

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"k8s.io/apimachinery/pkg/version"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	//go:embed kubeconfig_mock.json
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
		context       string
		opaSessionObj *cautils.OPASessionObj
		kubeConfig    *clientcmdapi.Config
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
					Report: &reporthandlingv2.PostureReport{
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
			name: "Test_getCloudMetadata_context_GKE",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reporthandlingv2.PostureReport{
						ClusterAPIServerInfo: nil,
					},
				},
				kubeConfig: kubeConfig,
				context:    "gke_xxx-xx-0000_us-central1-c_xxxx-1",
			},
			want: helpersv1.NewGKEMetadata(""),
		},
		{
			name: "Test_getCloudMetadata_context_EKS",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reporthandlingv2.PostureReport{
						ClusterAPIServerInfo: nil,
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
					Report: &reporthandlingv2.PostureReport{
						ClusterAPIServerInfo: nil,
					},
				},
				kubeConfig: kubeConfig,
				context:    "xxxx-2",
			},
			want: helpersv1.NewAKSMetadata(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.kubeConfig.CurrentContext = tt.args.context
			got := getCloudMetadata(tt.args.opaSessionObj, tt.args.kubeConfig)
			if got == nil {
				t.Errorf("getCloudMetadata() = %v, want %v", got, tt.want.Provider())
				return
			}
			if got.Provider() != tt.want.Provider() {
				t.Errorf("getCloudMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isGKE(t *testing.T) {
	type args struct {
		config  *clientcmdapi.Config
		context string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test_isGKE",
			args: args{
				config:  getKubeConfigMock(),
				context: "gke_xxx-xx-0000_us-central1-c_xxxx-1",
			},
			want: true,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			// set context
			tt.args.config.CurrentContext = tt.args.context
			if got := isGKE(tt.args.config); got != tt.want {
				t.Errorf("isGKE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isEKS(t *testing.T) {
	type args struct {
		config  *clientcmdapi.Config
		context string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test_isEKS",
			args: args{
				config:  getKubeConfigMock(),
				context: "arn:aws:eks:eu-west-1:xxx:cluster/xxxx",
			},
			want: true,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			// set context
			tt.args.config.CurrentContext = tt.args.context
			if got := isEKS(tt.args.config); got != tt.want {
				t.Errorf("isEKS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isAKS(t *testing.T) {
	type args struct {
		config  *clientcmdapi.Config
		context string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test_isAKS",
			args: args{
				config:  getKubeConfigMock(),
				context: "xxxx-2",
			},
			want: true,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			// set context
			tt.args.config.CurrentContext = tt.args.context
			if got := isAKS(tt.args.config); got != tt.want {
				t.Errorf("isAKS() = %v, want %v", got, tt.want)
			}
		})
	}
}

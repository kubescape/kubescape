package submit

import (
	"fmt"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/armosec/kubescape/v2/core/meta"
	"github.com/armosec/kubescape/v2/core/meta/cliinterfaces"
	v1 "github.com/armosec/kubescape/v2/core/meta/datastructures/v1"
	reporterv2 "github.com/armosec/kubescape/v2/core/pkg/resultshandling/reporter/v2"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
	"github.com/google/uuid"

	"github.com/armosec/rbac-utils/rbacscanner"
	"github.com/spf13/cobra"
)

var (
	rbacExamples = `
	# Submit cluster's Role-Based Access Control(RBAC)
	kubescape submit rbac

	# Submit cluster's Role-Based Access Control(RBAC) with account ID 
	kubescape submit rbac --account <account-id>
	`
)

// getRBACCmd represents the RBAC command
func getRBACCmd(ks meta.IKubescape, submitInfo *v1.Submit) *cobra.Command {
	return &cobra.Command{
		Use:     "rbac",
		Example: rbacExamples,
		Short:   "Submit cluster's Role-Based Access Control(RBAC)",
		Long:    ``,
		RunE: func(cmd *cobra.Command, args []string) error {

			k8s := k8sinterface.NewKubernetesApi()

			// get config
			clusterConfig := getTenantConfig(&submitInfo.Credentials, "", k8s)
			if err := clusterConfig.SetTenant(); err != nil {
				logger.L().Error("failed setting account ID", helpers.Error(err))
			}

			if clusterConfig.GetAccountID() == "" {
				return fmt.Errorf("account ID is not set, run 'kubescape submit rbac --account <account-id>'")
			}

			// list RBAC
			rbacObjects := cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, clusterConfig.GetAccountID(), clusterConfig.GetContextName()))

			// submit resources
			r := reporterv2.NewReportEventReceiver(clusterConfig.GetConfigObj(), uuid.NewString(), reporterv2.SubmitContextRBAC)

			submitInterfaces := cliinterfaces.SubmitInterfaces{
				ClusterConfig: clusterConfig,
				SubmitObjects: rbacObjects,
				Reporter:      r,
			}

			if err := ks.Submit(submitInterfaces); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}

}

// getKubernetesApi
func getKubernetesApi() *k8sinterface.KubernetesApi {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}
	return k8sinterface.NewKubernetesApi()
}
func getTenantConfig(credentials *cautils.Credentials, clusterName string, k8s *k8sinterface.KubernetesApi) cautils.ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return cautils.NewLocalConfig(getter.GetKSCloudAPIConnector(), credentials, clusterName)
	}
	return cautils.NewClusterConfig(k8s, getter.GetKSCloudAPIConnector(), credentials, clusterName)
}

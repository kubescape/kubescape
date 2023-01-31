package submit

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/kubescape/kubescape/v2/core/meta/cliinterfaces"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	reporterv2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter/v2"

	"github.com/kubescape/rbac-utils/rbacscanner"
	"github.com/spf13/cobra"
)

var (
	rbacExamples = fmt.Sprintf(`
	# Submit cluster's Role-Based Access Control(RBAC)
	%[1]s submit rbac

	# Submit cluster's Role-Based Access Control(RBAC) with account ID 
	%[1]s submit rbac --account <account-id>
	`, cautils.ExecName())
)

// getRBACCmd represents the RBAC command
func getRBACCmd(ks meta.IKubescape, submitInfo *v1.Submit) *cobra.Command {
	return &cobra.Command{
		Use:        "rbac",
		Deprecated: "This command is deprecated and will not be supported after 1/Jan/2023. Please use the 'scan' command instead.",
		Example:    rbacExamples,
		Short:      "Submit cluster's Role-Based Access Control(RBAC)",
		Long:       ``,
		RunE: func(_ *cobra.Command, args []string) error {

			if err := flagValidationSubmit(submitInfo); err != nil {
				return err
			}

			k8s := k8sinterface.NewKubernetesApi()

			// get config
			clusterConfig := getTenantConfig(&submitInfo.Credentials, "", "", k8s)
			if err := clusterConfig.SetTenant(); err != nil {
				logger.L().Error("failed setting account ID", helpers.Error(err))
			}

			if clusterConfig.GetAccountID() == "" {
				return fmt.Errorf("account ID is not set, run '%[1]s submit rbac --account <account-id>'", cautils.ExecName())
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

			if err := ks.Submit(context.TODO(), submitInterfaces); err != nil {
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
func getTenantConfig(credentials *cautils.Credentials, clusterName string, customClusterName string, k8s *k8sinterface.KubernetesApi) cautils.ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return cautils.NewLocalConfig(getter.GetKSCloudAPIConnector(), credentials, clusterName, customClusterName)
	}
	return cautils.NewClusterConfig(k8s, getter.GetKSCloudAPIConnector(), credentials, clusterName, customClusterName)
}

// Check if the flag entered are valid
func flagValidationSubmit(submitInfo *v1.Submit) error {

	// Validate the user's credentials
	return submitInfo.Credentials.Validate()
}

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/rbac-utils/rbacscanner"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
)

type RBACObjects struct {
	scanner *rbacscanner.RbacScannerFromK8sAPI
}

func NewRBACObjects(scanner *rbacscanner.RbacScannerFromK8sAPI) *RBACObjects {
	return &RBACObjects{scanner: scanner}
}

func (rbacObjects *RBACObjects) SetResourcesReport() (*reporthandling.PostureReport, error) {
	resources, err := rbacObjects.scanner.ListResources()
	if err != nil {
		return nil, err
	}
	return &reporthandling.PostureReport{
		ReportID:             uuid.NewV4().String(),
		ReportGenerationTime: time.Now().UTC(),
		CustomerGUID:         rbacObjects.scanner.CustomerGUID,
		ClusterName:          rbacObjects.scanner.ClusterName,
		RBACObjects:          *resources,
	}, nil
}

// rabcCmd represents the RBAC command
var rabcCmd = &cobra.Command{
	Use:   "rbac \nExample:\n$ kubescape submit rbac",
	Short: "Submit cluster's Role-Based Access Control(RBAC)",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {

		k8s := k8sinterface.NewKubernetesApi()

		// get config
		clusterConfig, err := getSubmittedClusterConfig(k8s)
		if err != nil {
			return err
		}

		clusterName := clusterConfig.GetClusterName()
		customerGUID := clusterConfig.GetCustomerGUID()

		// list RBAC
		rbacObjects := NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, customerGUID, clusterName))

		// submit resources
		r := reporter.NewReportEventReceiver(customerGUID, clusterName)

		submitInterfaces := cliinterfaces.SubmitInterfaces{
			ClusterConfig: clusterConfig,
			SubmitObjects: rbacObjects,
			Reporter:      r,
		}

		if err := clihandler.Submit(submitInterfaces); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	submitCmd.AddCommand(rabcCmd)
}

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/rbac-utils/rbacscanner"
	"github.com/armosec/rbac-utils/rbacutils"
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
	return &reporthandling.PostureReport{
		ReportID:             uuid.NewV4().String(),
		ReportGenerationTime: time.Now().UTC(),
		CustomerGUID:         rbacObjects.scanner.CustomerGUID,
		ClusterName:          rbacObjects.scanner.ClusterName,
	}, nil
}

func (rbacObjects *RBACObjects) ListAllResources() (map[string]workloadinterface.IMetadata, error) {
	resources, err := rbacObjects.scanner.ListResources()
	if err != nil {
		return nil, err
	}
	allresources, err := rbacObjects.rbacObjectsToResources(resources)
	if err != nil {
		return nil, err
	}
	return allresources, nil
}

func (rbacObjects *RBACObjects) rbacObjectsToResources(resources *rbacutils.RbacObjects) (map[string]workloadinterface.IMetadata, error) {
	allresources := map[string]workloadinterface.IMetadata{}
	// wrap rbac aggregated objects in IMetadata and add to allresources
	rbacIMeta, err := rbacutils.RbacObjectIMetadataWrapper(resources.Rbac)
	if err != nil {
		return nil, err
	}
	allresources[rbacIMeta.GetID()] = rbacIMeta
	rbacTableIMeta, err := rbacutils.RbacTableObjectIMetadataWrapper(resources.RbacT)
	if err != nil {
		return nil, err
	}
	allresources[rbacTableIMeta.GetID()] = rbacTableIMeta
	SA2WLIDmapIMeta, err := rbacutils.SA2WLIDmapIMetadataWrapper(resources.SA2WLIDmap)
	if err != nil {
		return nil, err
	}
	allresources[SA2WLIDmapIMeta.GetID()] = SA2WLIDmapIMeta

	// convert rbac k8s resources to IMetadata and add to allresources
	for _, cr := range resources.ClusterRoles.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("ClusterRole")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.Roles.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("Role")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.ClusterRoleBindings.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("ClusterRoleBinding")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.RoleBindings.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("RoleBinding")
		allresources[crIMeta.GetID()] = crIMeta
	}
	return allresources, nil
}

func convertToMap(obj interface{}) (map[string]interface{}, error) {
	var inInterface map[string]interface{}
	inrec, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(inrec, &inInterface)
	if err != nil {
		return nil, err
	}
	return inInterface, nil
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

		// list RBAC
		rbacObjects := NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, clusterConfig.GetCustomerGUID(), clusterConfig.GetClusterName()))

		// submit resources
		r := reporter.NewReportEventReceiver(clusterConfig.GetConfigObj())

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

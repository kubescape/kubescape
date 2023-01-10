package submit

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/kubescape/kubescape/v2/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/kubescape/kubescape/v2/core/meta/cliinterfaces"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	reporterv2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter/v2"

	"github.com/spf13/cobra"
)

var formatVersion string

type ResultsObject struct {
	filePath     string
	customerGUID string
	clusterName  string
}

func NewResultsObject(customerGUID, clusterName, filePath string) *ResultsObject {
	return &ResultsObject{
		filePath:     filePath,
		customerGUID: customerGUID,
		clusterName:  clusterName,
	}
}

func (resultsObject *ResultsObject) SetResourcesReport() (*reporthandlingv2.PostureReport, error) {
	// load framework results from json file
	report, err := loadResultsFromFile(resultsObject.filePath)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func (resultsObject *ResultsObject) ListAllResources() (map[string]workloadinterface.IMetadata, error) {
	return map[string]workloadinterface.IMetadata{}, nil
}

func getResultsCmd(ks meta.IKubescape, submitInfo *v1.Submit) *cobra.Command {
	var resultsCmd = &cobra.Command{
		Use:   fmt.Sprintf("results <json file>\nExample:\n$ %[1]s submit results path/to/results.json --format-version v2", cautils.ExecName()),
		Short: "Submit a pre scanned results file. The file must be in json format",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := flagValidationSubmit(submitInfo); err != nil {
				return err
			}

			if len(args) == 0 {
				return fmt.Errorf("missing results file")
			}

			k8s := getKubernetesApi()

			// get config
			clusterConfig := getTenantConfig(&submitInfo.Credentials, "", "", k8s)
			if err := clusterConfig.SetTenant(); err != nil {
				logger.L().Error("failed setting account ID", helpers.Error(err))
			}

			resultsObjects := NewResultsObject(clusterConfig.GetAccountID(), clusterConfig.GetContextName(), args[0])

			r := reporterv2.NewReportEventReceiver(clusterConfig.GetConfigObj(), uuid.NewString(), reporterv2.SubmitContextScan)

			submitInterfaces := cliinterfaces.SubmitInterfaces{
				ClusterConfig: clusterConfig,
				SubmitObjects: resultsObjects,
				Reporter:      r,
			}

			if err := ks.Submit(submitInterfaces); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}
	resultsCmd.PersistentFlags().StringVar(&formatVersion, "format-version", "v1", "Output object can be different between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")

	return resultsCmd
}
func loadResultsFromFile(filePath string) (*reporthandlingv2.PostureReport, error) {
	report := &reporthandlingv2.PostureReport{}
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(f, report); err != nil {
		return report, fmt.Errorf("failed to unmarshal results file: %s, make sure you run kubescape with '--format=json --format-version=v2'", err.Error())
	}
	return report, nil
}

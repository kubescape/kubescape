package submit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/resultshandling/reporter"
	reporterv1 "github.com/armosec/kubescape/resultshandling/reporter/v1"
	reporterv2 "github.com/armosec/kubescape/resultshandling/reporter/v2"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/google/uuid"
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

func (resultsObject *ResultsObject) SetResourcesReport() (*reporthandling.PostureReport, error) {
	// load framework results from json file
	frameworkReports, err := loadResultsFromFile(resultsObject.filePath)
	if err != nil {
		return nil, err
	}
	return &reporthandling.PostureReport{
		FrameworkReports:     frameworkReports,
		ReportID:             uuid.NewString(),
		ReportGenerationTime: time.Now().UTC(),
		CustomerGUID:         resultsObject.customerGUID,
		ClusterName:          resultsObject.clusterName,
	}, nil
}

func (resultsObject *ResultsObject) ListAllResources() (map[string]workloadinterface.IMetadata, error) {
	return map[string]workloadinterface.IMetadata{}, nil
}

func getResultsCmd() *cobra.Command {
	var resultsCmd = &cobra.Command{
		Use:   "results <json file>\nExample:\n$ kubescape submit results path/to/results.json --format-version v2",
		Short: "Submit a pre scanned results file. The file must be in json format",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing results file")
			}

			k8s := getKubernetesApi()

			// get config
			clusterConfig := getTenantConfig(submitInfo.Account, "", k8s)
			if err := clusterConfig.SetTenant(); err != nil {
				logger.L().Error("failed setting account ID", helpers.Error(err))
			}

			resultsObjects := NewResultsObject(clusterConfig.GetAccountID(), clusterConfig.GetClusterName(), args[0])

			// submit resources
			var r reporter.IReport
			switch formatVersion {
			case "v2":
				r = reporterv2.NewReportEventReceiver(clusterConfig.GetConfigObj(), "")
			default:
				logger.L().Warning("Deprecated results version. run with '--format-version' flag", helpers.String("your version", formatVersion), helpers.String("latest version", "v2"))
				r = reporterv1.NewReportEventReceiver(clusterConfig.GetConfigObj())
			}

			submitInterfaces := cliinterfaces.SubmitInterfaces{
				ClusterConfig: clusterConfig,
				SubmitObjects: resultsObjects,
				Reporter:      r,
			}

			if err := clihandler.Submit(submitInterfaces); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}
	resultsCmd.PersistentFlags().StringVar(&formatVersion, "format-version", "v1", "Output object can be differnet between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")

	return resultsCmd
}
func loadResultsFromFile(filePath string) ([]reporthandling.FrameworkReport, error) {
	frameworkReports := []reporthandling.FrameworkReport{}
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(f, &frameworkReports); err != nil {
		frameworkReport := reporthandling.FrameworkReport{}
		if err = json.Unmarshal(f, &frameworkReport); err != nil {
			return frameworkReports, err
		}
		frameworkReports = append(frameworkReports, frameworkReport)
	}
	return frameworkReports, nil
}

package clihandler

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resultshandling"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	scanInfo      *cautils.ScanInfo
}

var SupportedFrameworks = []string{"nsa", "mitre"}
var ValidFrameworks = strings.Join(SupportedFrameworks, ", ")

func CliSetup(scanInfo cautils.ScanInfo) error {

	clusterConfig, k8s := scanInfo.SetClusterConfig()

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	// policy handler setup
	policyHandler := policyhandler.NewPolicyHandler(&processNotification, k8s)

	if err := clusterConfig.SetConfig(scanInfo.Account); err != nil {
		fmt.Println(err)
	}

	cautils.ClusterName = clusterConfig.GetClusterName()
	cautils.CustomerGUID = clusterConfig.GetCustomerGUID()

	// cli handler setup
	go func() {
		cli := NewCLIHandler(policyHandler, scanInfo)
		if err := cli.Scan(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	// processor setup - rego run
	go func() {
		opaprocessorObj := opaprocessor.NewOPAProcessorHandler(&processNotification, &reportResults)
		opaprocessorObj.ProcessRulesListenner()
	}()

	resultsHandling := resultshandling.NewResultsHandler(&reportResults, reporter.NewReportEventReceiver(), printer.NewPrinter(scanInfo.Format, scanInfo.Output))
	score := resultsHandling.HandleResults(scanInfo)

	// print report url
	if scanInfo.FrameworkScan {
		clusterConfig.GenerateURL()
	}

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is bellow threshold")
	}

	return nil
}

func NewCLIHandler(policyHandler *policyhandler.PolicyHandler, scanInfo cautils.ScanInfo) *CLIHandler {
	return &CLIHandler{
		scanInfo:      &scanInfo,
		policyHandler: policyHandler,
	}
}

func (clihandler *CLIHandler) Scan() error {
	cautils.ScanStartDisplay()
	policyNotification := &reporthandling.PolicyNotification{
		NotificationType: reporthandling.TypeExecPostureScan,
		Rules: []reporthandling.PolicyIdentifier{
			clihandler.scanInfo.PolicyIdentifier,
		},
		Designators: armotypes.PortalDesignator{},
	}
	switch policyNotification.NotificationType {
	case reporthandling.TypeExecPostureScan:
		if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification, clihandler.scanInfo); err != nil {
			return err
		}

	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

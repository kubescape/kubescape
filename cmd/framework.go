package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/armosec/kubescape/cautils/opapolicy"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resultshandling"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"

	"github.com/spf13/cobra"
)

var scanInfo cautils.ScanInfo
var supportedFrameworks = []string{"nsa", "mitre"}

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	scanInfo      *cautils.ScanInfo
}

var frameworkCmd = &cobra.Command{
	Use:       "framework <framework name> [`<glob patter>`/`-`] [flags]",
	Short:     fmt.Sprintf("The framework you wish to use. Supported frameworks: %s", strings.Join(supportedFrameworks, ", ")),
	Long:      "Execute a scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
	ValidArgs: supportedFrameworks,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 && !(cmd.Flags().Lookup("use-from").Changed) {
			return fmt.Errorf("requires at least one argument")
		} else if len(args) > 0 {
			if !isValidFramework(strings.ToLower(args[0])) {
				return fmt.Errorf(fmt.Sprintf("supported frameworks: %s", strings.Join(supportedFrameworks, ", ")))
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanInfo.PolicyIdentifier = opapolicy.PolicyIdentifier{}
		scanInfo.PolicyIdentifier.Kind = opapolicy.KindFramework

		if !(cmd.Flags().Lookup("use-from").Changed) {
			scanInfo.PolicyIdentifier.Name = strings.ToLower(args[0])
		}
		if len(args) > 0 {
			if len(args[1:]) == 0 || args[1] != "-" {
				scanInfo.InputPatterns = args[1:]
			} else { // store stout to file
				tempFile, err := os.CreateTemp(".", "tmp-kubescape*.yaml")
				if err != nil {
					return err
				}
				defer os.Remove(tempFile.Name())

				if _, err := io.Copy(tempFile, os.Stdin); err != nil {
					return err
				}
				scanInfo.InputPatterns = []string{tempFile.Name()}
			}
		}
		scanInfo.Init()
		cautils.SetSilentMode(scanInfo.Silent)
		err := CliSetup()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func isValidFramework(framework string) bool {
	return cautils.StringInSlice(supportedFrameworks, framework) != cautils.ValueNotFound
}

func init() {
	scanCmd.AddCommand(frameworkCmd)
	scanInfo = cautils.ScanInfo{}
	frameworkCmd.Flags().StringVar(&scanInfo.UseFrom, "use-from", "", "Path to load framework from")
	frameworkCmd.Flags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load framework from default path")
	frameworkCmd.Flags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to file containing list of exceptions")
	frameworkCmd.Flags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from check")
	frameworkCmd.Flags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output format. supported formats: "pretty-printer"/"json"/"junit"`)
	frameworkCmd.Flags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. print output to file and not stdout")
	frameworkCmd.Flags().BoolVarP(&scanInfo.Silent, "silent", "s", false, "Silent progress messages")
	frameworkCmd.Flags().Uint16VarP(&scanInfo.FailThreshold, "fail-threshold", "t", 0, "Failure threshold is the percent bellow which the command fails and returns exit code -1")
	frameworkCmd.Flags().BoolVarP(&scanInfo.DoNotSendResults, "results-locally", "", false, "Kubescape sends scan results to Armosec backend to allow users to control exceptions and maintain chronological scan results. Use this flag if you do not wish to use these features")
}

func CliSetup() error {
	flag.Parse()

	if 100 < scanInfo.FailThreshold {
		fmt.Println("bad argument: out of range threshold")
		os.Exit(1)
	}

	var k8s *k8sinterface.KubernetesApi
	if !scanInfo.ScanRunningCluster() {
		k8sinterface.ConnectedToCluster = false
	} else {
		k8s = k8sinterface.NewKubernetesApi()
	}

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	// policy handler setup
	policyHandler := policyhandler.NewPolicyHandler(&processNotification, k8s)

	// load cluster config
	var clusterConfig cautils.IClusterConfig
	if !scanInfo.DoNotSendResults && k8sinterface.ConnectedToCluster {
		clusterConfig = cautils.NewClusterConfig(k8s, getter.NewArmoAPI())
	} else {
		clusterConfig = cautils.NewEmptyConfig()
	}

	if err := clusterConfig.SetCustomerGUID(); err != nil {
		fmt.Println(err)
	}
	cautils.CustomerGUID = clusterConfig.GetCustomerGUID()
	cautils.ClusterName = k8sinterface.GetClusterName()

	// cli handler setup
	go func() {
		cli := NewCLIHandler(policyHandler)
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
	score := resultsHandling.HandleResults()

	// print report url
	clusterConfig.GenerateURL()

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is bellow threshold")
	}

	return nil
}

func NewCLIHandler(policyHandler *policyhandler.PolicyHandler) *CLIHandler {
	return &CLIHandler{
		scanInfo:      &scanInfo,
		policyHandler: policyHandler,
	}
}

func (clihandler *CLIHandler) Scan() error {
	cautils.ScanStartDisplay()
	policyNotification := &opapolicy.PolicyNotification{
		NotificationType: opapolicy.TypeExecPostureScan,
		Rules: []opapolicy.PolicyIdentifier{
			clihandler.scanInfo.PolicyIdentifier,
		},
		Designators: armotypes.PortalDesignator{},
	}
	switch policyNotification.NotificationType {
	case opapolicy.TypeExecPostureScan:
		//
		if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification, clihandler.scanInfo); err != nil {
			return err
		}
	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

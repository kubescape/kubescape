package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"kubescape/cautils"
	"kubescape/cautils/armotypes"
	"kubescape/cautils/k8sinterface"
	"kubescape/cautils/opapolicy"
	"kubescape/opaprocessor"
	"kubescape/policyhandler"
	"kubescape/printer"
	"os"

	"github.com/spf13/cobra"
)

var scanInfo opapolicy.ScanInfo
var supportedFrameworks = []string{"nsa", "mitre"}

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	scanInfo      *opapolicy.ScanInfo
}

var frameworkCmd = &cobra.Command{
	Use:       "framework <framework name> [`<glob patter>`/`-`] [flags]",
	Short:     "The framework you wish to use. Supported frameworks: nsa",
	Long:      "Execute a scan on a running Kubernetes cluster or yaml/json files (use glob) or `-` for stdin",
	ValidArgs: supportedFrameworks,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires at least one argument")
		}
		if !isValidFramework(args[0]) {
			return errors.New("supported frameworks: nsa")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanInfo.PolicyIdentifier = opapolicy.PolicyIdentifier{}
		scanInfo.PolicyIdentifier.Kind = opapolicy.KindFramework
		scanInfo.PolicyIdentifier.Name = args[0]

		if len(args[1:]) == 0 || args[1] != "-" {
			scanInfo.InputPatterns = args[1:]
		} else { // store stout to file
			tempFile, err := ioutil.TempFile(".", "tmp-kubescape*.yaml")
			if err != nil {
				return err
			}
			defer os.Remove(tempFile.Name())

			if _, err := io.Copy(tempFile, os.Stdin); err != nil {
				return err
			}
			scanInfo.InputPatterns = []string{tempFile.Name()}
		}
		cautils.SetSilentMode(scanInfo.Silent)
		CliSetup()

		return nil
	},
}

func isValidFramework(framework string) bool {
	return cautils.StringInSlice(supportedFrameworks, framework) != cautils.ValueNotFound
}

func init() {
	scanCmd.AddCommand(frameworkCmd)
	scanInfo = opapolicy.ScanInfo{}
	frameworkCmd.Flags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "namespaces to exclude from check")
	frameworkCmd.Flags().StringVarP(&scanInfo.Output, "output", "o", "pretty-printer", "output format. supported formats: 'pretty-printer'/'json'/'junit'")
	frameworkCmd.Flags().BoolVarP(&scanInfo.Silent, "silent", "s", false, "silent progress output")
}

func CliSetup() error {
	flag.Parse()

	k8s := k8sinterface.NewKubernetesApi()

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	// policy handler setup
	policyHandler := policyhandler.NewPolicyHandler(&processNotification, k8s)

	// cli handler setup
	cli := NewCLIHandler(policyHandler)
	if err := cli.Scan(); err != nil {
		panic(err)
	}

	// processor setup - rego run
	go func() {
		reporterObj := opaprocessor.NewOPAProcessor(&processNotification, &reportResults)
		reporterObj.ProcessRulesListenner()
	}()
	p := printer.NewPrinter(&reportResults, scanInfo.Output)
	p.ActionPrint()

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
		go func() {
			if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification, clihandler.scanInfo); err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(0)
			}
		}()
	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

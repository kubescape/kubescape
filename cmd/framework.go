package cmd

import (
	"fmt"
	"kube-escape/cautils"
	"kube-escape/cautils/armotypes"
	"kube-escape/cautils/k8sinterface"
	"kube-escape/cautils/opapolicy"
	"kube-escape/opaprocessor"
	"kube-escape/policyhandler"
	"kube-escape/printer"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var scanInfo opapolicy.ScanInfo

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	scanInfo      *opapolicy.ScanInfo
}

var frameworkCmd = &cobra.Command{
	Use:       "framework <framework name>",
	Short:     "The framework you wish to use. Supported frameworks: nsa, mitre",
	Long:      ``,
	ValidArgs: []string{"nsa", "mitre"},
	Args:      cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		scanInfo.PolicyIdentifier = opapolicy.PolicyIdentifier{}
		scanInfo.PolicyIdentifier.Kind = "Framework"
		scanInfo.PolicyIdentifier.Name = strings.Join(args, ",")
		CliSetup()
	},
}

func init() {
	scanCmd.AddCommand(frameworkCmd)
	scanInfo = opapolicy.ScanInfo{}
	frameworkCmd.Flags().StringVarP(&scanInfo.ExcludedNamespaces, "excluded-namespaces", "e", "", "namespaces to exclude from check")
	frameworkCmd.Flags().StringVarP(&scanInfo.Output, "output", "o", "", "output format")
}

func CliSetup() error {
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
	p := printer.NewPrinter(&reportResults)
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
	cautils.InfoDisplay(os.Stdout, "ARMO security scanner starting\n")

	policyNotification := &opapolicy.PolicyNotification{
		NotificationType: opapolicy.TypeExecPostureScan,
		Rules: []opapolicy.PolicyIdentifier{
			*&clihandler.scanInfo.PolicyIdentifier,
		},
		Designators: armotypes.PortalDesignator{},
	}

	switch policyNotification.NotificationType {
	case opapolicy.TypeExecPostureScan:
		go func() {
			if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification, scanInfo.ExcludedNamespaces); err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(0)
			}
		}()
	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

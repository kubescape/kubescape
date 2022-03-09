package cmd

import (
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/spf13/cobra"
)

var scanInfo cautils.ScanInfo

var scanCmdExamples = `
  Scan command is for scanning an existing cluster or kubernetes manifest files based on pre-defind frameworks 
  
  # Scan current cluster with all frameworks
  kubescape scan --submit --enable-host-scan

  # Scan kubernetes YAML manifest files
  kubescape scan *.yaml

  # Scan and save the results in the JSON format
  kubescape scan --format json --output results.json

  # Display all resources
  kubescape scan --verbose

  # Scan different clusters from the kubectl context 
  kubescape scan --kube-context <kubernetes context>
  
`

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Scan the current running cluster or yaml files",
	Long:    `The action you want to perform`,
	Example: scanCmdExamples,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			if args[0] != "framework" && args[0] != "control" {
				scanInfo.ScanAll = true
				return frameworkCmd.RunE(cmd, append([]string{"all"}, args...))
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			scanInfo.ScanAll = true
			return frameworkCmd.RunE(cmd, []string{"all"})
		}
		return nil
	},
}

func frameworkInitConfig() {
	k8sinterface.SetClusterContextName(scanInfo.KubeContext)
}
func init() {

	cobra.OnInitialize(frameworkInitConfig)

	rootCmd.AddCommand(scanCmd)

	scanCmd.PersistentFlags().StringVarP(&scanInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.KubeContext, "kube-context", "", "", "Kube context. Default will use the current-context")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsInputs, "controls-config", "", "Path to an controls-config obj. If not set will download controls-config from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseArtifactsFrom, "use-artifacts-from", "", "Load artifacts from local directory. If not used will download them")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. Recommended: kube-system,kube-public")
	scanCmd.PersistentFlags().Float32VarP(&scanInfo.FailThreshold, "fail-threshold", "t", 100, "Failure threshold is the percent above which the command fails and returns exit code 1")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output format. Supported formats: "pretty-printer","json","junit","prometheus","pdf"`)
	scanCmd.PersistentFlags().StringVar(&scanInfo.IncludeNamespaces, "include-namespaces", "", "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Local, "keep-local", "", false, "If you do not want your Kubescape results reported to Armo backend. Use this flag if you ran with the '--submit' flag in the past and you do not want to submit your current scan results")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.VerboseMode, "verbose", false, "Display all of the input resources and not only failed resources")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load local policy object from default path. If not used will download latest")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.UseFrom, "use-from", nil, "Load local policy object from specified path. If not used will download latest")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Silent, "silent", "s", false, "Silent progress messages")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Submit, "submit", "", false, "Send the scan results to Armo management portal where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	scanCmd.PersistentFlags().StringVar(&scanInfo.HostSensorYamlPath, "host-scan-yaml", "", "Override default host sensor DaemonSet. Use this flag cautiously")
	scanCmd.PersistentFlags().StringVar(&scanInfo.FormatVersion, "format-version", "v1", "Output object can be differnet between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")

	// hidden flags
	scanCmd.PersistentFlags().MarkHidden("host-scan-yaml") // this flag should be used very cautiously. We prefer users will not use it at all unless the DaemonSet can not run pods on the nodes
	scanCmd.PersistentFlags().MarkHidden("silent")         // this flag should be deprecated since we added the --logger support
	// scanCmd.PersistentFlags().MarkHidden("format-version") // meant for testing different output approaches and not for common use

	hostF := scanCmd.PersistentFlags().VarPF(&scanInfo.HostSensorEnabled, "enable-host-scan", "", "Deploy ARMO K8s host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls. Yaml file: https://raw.githubusercontent.com/armosec/kubescape/master/hostsensorutils/hostsensor.yaml")
	hostF.NoOptDefVal = "true"
	hostF.DefValue = "false, for no TTY in stdin"

}

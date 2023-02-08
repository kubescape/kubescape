package scan

import (
	"flag"
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

var scanCmdExamples = fmt.Sprintf(`
  Scan command is for scanning an existing cluster or kubernetes manifest files based on pre-defined frameworks 
  
  # Scan current cluster with all frameworks
  %[1]s scan --enable-host-scan --verbose

  # Scan kubernetes YAML manifest files
  %[1]s scan .

  # Scan and save the results in the JSON format
  %[1]s scan --format json --output results.json --format-version=v2

  # Display all resources
  %[1]s scan --verbose

  # Scan different clusters from the kubectl context 
  %[1]s scan --kube-context <kubernetes context>
`, cautils.ExecName())

func GetScanCommand(ks meta.IKubescape) *cobra.Command {
	var scanInfo cautils.ScanInfo

	// scanCmd represents the scan command
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan the current running cluster or yaml files",
		Long:    `The action you want to perform`,
		Example: scanCmdExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if args[0] != "framework" && args[0] != "control" {
					return getFrameworkCmd(ks, &scanInfo).RunE(cmd, append([]string{"all"}, args...))
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) == 0 {
				return getFrameworkCmd(ks, &scanInfo).RunE(cmd, []string{strings.Join(getter.NativeFrameworks, ",")})
			}
			return nil
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			k8sinterface.SetClusterContextName(scanInfo.KubeContext)

		},
		PostRun: func(cmd *cobra.Command, args []string) {
			// TODO - revert context
		},
	}

	scanCmd.PersistentFlags().StringVarP(&scanInfo.Credentials.Account, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.CreateAccount, "create-account", false, "Create a Kubescape SaaS account ID account ID is not found in cache. After creating the account, the account ID will be saved in cache. In addition, the scanning results will be uploaded to the Kubescape SaaS")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Credentials.ClientID, "client-id", "", "", "Kubescape SaaS client ID. Default will load client ID from cache, read more - https://hub.armosec.io/docs/authentication")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Credentials.SecretKey, "secret-key", "", "", "Kubescape SaaS secret key. Default will load secret key from cache, read more - https://hub.armosec.io/docs/authentication")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.KubeContext, "kube-context", "", "", "Kube context. Default will use the current-context")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsInputs, "controls-config", "", "Path to an controls-config obj. If not set will download controls-config from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseArtifactsFrom, "use-artifacts-from", "", "Load artifacts from local directory. If not used will download them")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. Notice, when running with `exclude-namespace` kubescape does not scan cluster-scoped objects.")

	scanCmd.PersistentFlags().Float32VarP(&scanInfo.FailThreshold, "fail-threshold", "t", 100, "Failure threshold is the percent above which the command fails and returns exit code 1")

	scanCmd.PersistentFlags().StringVar(&scanInfo.FailThresholdSeverity, "severity-threshold", "", "Severity threshold is the severity of failed controls at which the command fails and returns exit code 1")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", `Output file format. Supported formats: "pretty-printer", "json", "junit", "prometheus", "pdf", "html", "sarif"`)
	scanCmd.PersistentFlags().StringVar(&scanInfo.IncludeNamespaces, "include-namespaces", "", "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Local, "keep-local", "", false, "If you do not want your Kubescape results reported to configured backend.")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display all of the input resources and not only failed resources")
	scanCmd.PersistentFlags().StringVar(&scanInfo.View, "view", string(cautils.ResourceViewType), fmt.Sprintf("View results based on the %s/%s. default is --view=%s", cautils.ResourceViewType, cautils.ControlViewType, cautils.ResourceViewType))
	scanCmd.PersistentFlags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load local policy object from default path. If not used will download latest")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.UseFrom, "use-from", nil, "Load local policy object from specified path. If not used will download latest")
	scanCmd.PersistentFlags().StringVar(&scanInfo.HostSensorYamlPath, "host-scan-yaml", "", "Override default host scanner DaemonSet. Use this flag cautiously")
	scanCmd.PersistentFlags().StringVar(&scanInfo.FormatVersion, "format-version", "v2", "Output object can be different between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")
	scanCmd.PersistentFlags().StringVar(&scanInfo.CustomClusterName, "cluster-name", "", "Set the custom name of the cluster. Not same as the kube-context flag")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Submit, "submit", "", false, "Submit the scan results to Kubescape SaaS where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.OmitRawResources, "omit-raw-resources", "", false, "Omit raw resources from the output. By default the raw resources are included in the output")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.PrintAttackTree, "print-attack-tree", "", false, "Print attack tree")

	scanCmd.PersistentFlags().MarkDeprecated("silent", "use '--logger' flag instead. Flag will be removed at 1.May.2022")

	// hidden flags
	scanCmd.PersistentFlags().MarkHidden("host-scan-yaml") // this flag should be used very cautiously. We prefer users will not use it at all unless the DaemonSet can not run pods on the nodes
	scanCmd.PersistentFlags().MarkHidden("omit-raw-resources")
	scanCmd.PersistentFlags().MarkHidden("print-attack-tree")

	// Retrieve --kubeconfig flag from https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/cmd.go
	scanCmd.PersistentFlags().AddGoFlag(flag.Lookup("kubeconfig"))

	hostF := scanCmd.PersistentFlags().VarPF(&scanInfo.HostSensorEnabled, "enable-host-scan", "", "Deploy Kubescape host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls. Yaml file: https://github.com/kubescape/kubescape/blob/master/core/pkg/hostsensorutils/hostsensor.yaml")
	hostF.NoOptDefVal = "true"
	hostF.DefValue = "false, for no TTY in stdin"

	scanCmd.AddCommand(getControlCmd(ks, &scanInfo))
	scanCmd.AddCommand(getFrameworkCmd(ks, &scanInfo))

	return scanCmd
}

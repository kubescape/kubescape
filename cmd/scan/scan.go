package scan

import (
	"context"
	"flag"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
)

var scanCmdExamples = fmt.Sprintf(`
  Scan command is for scanning an existing cluster or kubernetes manifest files based on pre-defined frameworks 
  
  # Scan current cluster
  %[1]s scan

  # Scan kubernetes manifest files 
  %[1]s scan .

  # Scan and save the results in the JSON format
  %[1]s scan --format json --output results.json

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
		Short:   "Scan a Kubernetes cluster or YAML files for image vulnerabilities and misconfigurations",
		Long:    `The action you want to perform`,
		Example: scanCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanInfo.View == string(cautils.SecurityViewType) {
				setSecurityViewScanInfo(args, &scanInfo)

				if err := securityScan(scanInfo, ks); err != nil {
					logger.L().Fatal(err.Error())
				}
			} else if len(args) == 0 || (args[0] != "framework" && args[0] != "control") {
				if err := getFrameworkCmd(ks, &scanInfo).RunE(cmd, append([]string{strings.Join(getter.NativeFrameworks, ",")}, args...)); err != nil {
					logger.L().Fatal(err.Error())
				}
			} else {
				return fmt.Errorf("kubescape did not do anything")
			}

			return nil
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			// TODO - revert context
		},
	}

	scanCmd.PersistentFlags().StringVarP(&scanInfo.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.AccessKey, "access-key", "", "", "Kubescape SaaS access key. Default will load access key from cache")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsInputs, "controls-config", "", "Path to an controls-config obj. If not set will download controls-config from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseArtifactsFrom, "use-artifacts-from", "", "Load artifacts from local directory. If not used will download them")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. e.g: --exclude-namespaces ns-a,ns-b. Notice, when running with `exclude-namespace` kubescape does not scan cluster-scoped objects.")

	scanCmd.PersistentFlags().Float32VarP(&scanInfo.FailThreshold, "fail-threshold", "t", 100, "Failure threshold is the percent above which the command fails and returns exit code 1")
	scanCmd.PersistentFlags().Float32VarP(&scanInfo.ComplianceThreshold, "compliance-threshold", "", 0, "Compliance threshold is the percent below which the command fails and returns exit code 1")

	scanCmd.PersistentFlags().StringVar(&scanInfo.FailThresholdSeverity, "severity-threshold", "", "Severity threshold is the severity of failed controls at which the command fails and returns exit code 1")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output file format. Supported formats: "pretty-printer", "json", "junit", "prometheus", "pdf", "html", "sarif"`)
	scanCmd.PersistentFlags().StringVar(&scanInfo.IncludeNamespaces, "include-namespaces", "", "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Local, "keep-local", "", false, "If you do not want your Kubescape results reported to configured backend.")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display all of the input resources and not only failed resources")
	scanCmd.PersistentFlags().StringVar(&scanInfo.View, "view", string(cautils.SecurityViewType), fmt.Sprintf("View results based on the %s/%s/%s. default is --view=%s", cautils.ResourceViewType, cautils.ControlViewType, cautils.SecurityViewType, cautils.SecurityViewType))
	scanCmd.PersistentFlags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load local policy object from default path. If not used will download latest")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.UseFrom, "use-from", nil, "Load local policy object from specified path. If not used will download latest")
	scanCmd.PersistentFlags().StringVar(&scanInfo.HostSensorYamlPath, "host-scan-yaml", "", "Override default host scanner DaemonSet. Use this flag cautiously")
	scanCmd.PersistentFlags().StringVar(&scanInfo.FormatVersion, "format-version", "v2", "Output object can be different between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")
	scanCmd.PersistentFlags().StringVar(&scanInfo.CustomClusterName, "cluster-name", "", "Set the custom name of the cluster. Not same as the kube-context flag")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Submit, "submit", "", false, "Submit the scan results to Kubescape SaaS where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.OmitRawResources, "omit-raw-resources", "", false, "Omit raw resources from the output. By default the raw resources are included in the output")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.PrintAttackTree, "print-attack-tree", "", false, "Print attack tree")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.ScanImages, "scan-images", "", false, "Scan resources images")

	scanCmd.PersistentFlags().MarkDeprecated("fail-threshold", "use '--compliance-threshold' flag instead. Flag will be removed at 1.Dec.2023")
	scanCmd.PersistentFlags().MarkDeprecated("create-account", "Create account is no longer supported. In case of a missing Account ID and a configured backend server, a new account id will be generated automatically by Kubescape. Feel free to contact the Kubescape maintainers for more information.")

	// hidden flags
	scanCmd.PersistentFlags().MarkHidden("omit-raw-resources")
	scanCmd.PersistentFlags().MarkHidden("print-attack-tree")
	scanCmd.PersistentFlags().MarkHidden("format-version")

	// Retrieve --kubeconfig flag from https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/cmd.go
	scanCmd.PersistentFlags().AddGoFlag(flag.Lookup("kubeconfig"))

	hostF := scanCmd.PersistentFlags().VarPF(&scanInfo.HostSensorEnabled, "enable-host-scan", "", "Deploy Kubescape host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls. Yaml file: https://github.com/kubescape/kubescape/blob/master/core/pkg/hostsensorutils/hostsensor.yaml")
	hostF.NoOptDefVal = "true"
	hostF.DefValue = "false, for no TTY in stdin"
	scanCmd.PersistentFlags().MarkHidden("enable-host-scan")
	scanCmd.PersistentFlags().MarkDeprecated("enable-host-scan", "To activate the host scanner capability, proceed with the installation of the kubescape operator chart found here: https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator. The flag will be removed at 1.Dec.2023")

	scanCmd.PersistentFlags().MarkHidden("host-scan-yaml") // this flag should be used very cautiously. We prefer users will not use it at all unless the DaemonSet can not run pods on the nodes
	scanCmd.PersistentFlags().MarkDeprecated("host-scan-yaml", "To activate the host scanner capability, proceed with the installation of the kubescape operator chart found here: https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator. The flag will be removed at 1.Dec.2023")

	scanCmd.AddCommand(getControlCmd(ks, &scanInfo))
	scanCmd.AddCommand(getFrameworkCmd(ks, &scanInfo))
	scanCmd.AddCommand(getWorkloadCmd(ks, &scanInfo))

	scanCmd.AddCommand(getImageCmd(ks, &scanInfo))

	return scanCmd
}

func setSecurityViewScanInfo(args []string, scanInfo *cautils.ScanInfo) {
	if len(args) > 0 {
		scanInfo.SetScanType(cautils.ScanTypeRepo)
		scanInfo.InputPatterns = args
		scanInfo.SetPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)
	} else {
		scanInfo.SetScanType(cautils.ScanTypeCluster)
		scanInfo.SetPolicyIdentifiers([]string{"clusterscan", "mitre", "nsa"}, v1.KindFramework)
	}
}

func securityScan(scanInfo cautils.ScanInfo, ks meta.IKubescape) error {

	ctx := context.TODO()

	results, err := ks.Scan(ctx, &scanInfo)
	if err != nil {
		return err
	}

	if err = results.HandleResults(ctx); err != nil {
		return err
	}

	enforceSeverityThresholds(results.GetData().Report.SummaryDetails.GetResourcesSeverityCounters(), &scanInfo, terminateOnExceedingSeverity)

	return nil
}

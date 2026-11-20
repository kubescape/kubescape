package prerequisites

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/sizing-checker/pkg/checks/connectivitycheck"
	"github.com/kubescape/sizing-checker/pkg/checks/ebpfcheck"
	"github.com/kubescape/sizing-checker/pkg/checks/pvcheck"
	"github.com/kubescape/sizing-checker/pkg/checks/sizing"
	"github.com/kubescape/sizing-checker/pkg/common"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	buildKubeClient    = newKubeClient
	collectClusterData = common.CollectClusterData
)

var prerequisitesCmdExamples = fmt.Sprintf(`
  # Check prerequisites for installing Kubescape Operator in the current cluster
  %[1]s prerequisites

  # Check prerequisites using a specific kubeconfig file
  %[1]s prerequisites --kubeconfig /path/to/kubeconfig

  # Check prerequisites in another context of the kubeconfig
  %[1]s prerequisites --kube-context staging
`, cautils.ExecName())

func GetPreReqCmd(ks meta.IKubescape) *cobra.Command {
	var kubeconfigPath *string

	// preReqCmd represents the prerequisites command
	preReqCmd := &cobra.Command{
		Use:     "prerequisites",
		Short:   "Check prerequisites for installing Kubescape Operator",
		Example: prerequisitesCmdExamples,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ks != nil && ks.Context() != nil {
				ctx = ks.Context()
			}
			path := ""
			if cmd.Flags().Changed("kubeconfig") {
				path = strings.TrimSpace(*kubeconfigPath)
				if path == "" {
					return errors.New("--kubeconfig requires a file path")
				}
			}
			// --kube-context is declared on the root command, so it is not
			// there when this command is built on its own.
			kubeContext, _ := cmd.Flags().GetString("kube-context")
			return runPrerequisites(ctx, path, kubeContext)
		},
	}

	kubeconfigPath = preReqCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file. If not set, in-cluster config is used, or $KUBECONFIG and then $HOME/.kube/config if outside a cluster.")

	return preReqCmd
}

// newKubeClient builds the client the checks run against. Like
// common.BuildKubeClient, it takes the in-cluster config when there is one.
// Outside a cluster it picks the kubeconfig the way kubectl and the other
// commands do: --kubeconfig, else $KUBECONFIG, else $HOME/.kube/config; and the
// context named by --kube-context, else the file's current-context.
// common.BuildKubeClient only knows the one file and its current-context.
func newKubeClient(kubeconfigPath, kubeContext string) (*kubernetes.Clientset, bool) {
	config, err := rest.InClusterConfig()
	inCluster := err == nil
	if !inCluster {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		rules.ExplicitPath = kubeconfigPath
		overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
		if err != nil {
			logger.L().Error("Could not load in-cluster or local kubeconfig", helpers.Error(err))
			return nil, false
		}
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.L().Error("Failed to create Kubernetes clientset", helpers.Error(err))
		return nil, inCluster
	}
	return clientSet, inCluster
}

// runPrerequisites collects cluster data and runs operator prerequisite checks.
// Collection failures must abort before checks/report generation: partial data
// previously produced false-negative PV results and unsafe Helm recommendations
// while still exiting 0.
func runPrerequisites(ctx context.Context, kubeconfigPath, kubeContext string) error {
	kubeconfigPath = strings.TrimSpace(kubeconfigPath)
	clientSet, inCluster := buildKubeClient(kubeconfigPath, kubeContext)
	if clientSet == nil {
		return fmt.Errorf("could not create kube client")
	}

	clusterData, err := collectClusterData(ctx, clientSet)
	if err != nil {
		logger.L().Error("Failed to collect cluster data", helpers.Error(err))
		return fmt.Errorf("failed to collect cluster data: %w", err)
	}

	sizingResult := sizing.RunSizingChecker(clusterData)
	pvResult := pvcheck.RunPVProvisioningCheck(ctx, clientSet, clusterData, inCluster)
	connectivityResult := connectivitycheck.RunConnectivityChecks(ctx, clientSet, clusterData, inCluster)
	ebpfResult := ebpfcheck.RunEbpfCheck(ctx, clientSet, clusterData, inCluster)

	finalReport := common.BuildReportData(clusterData, sizingResult, pvResult, connectivityResult, ebpfResult)
	finalReport.InCluster = inCluster

	common.GenerateOutput(finalReport, inCluster)
	return nil
}

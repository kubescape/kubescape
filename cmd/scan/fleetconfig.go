package scan

import (
	"fmt"
	"slices"

	"github.com/kubescape/kubescape/v4/core/cautils"
	fleetconfigv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/fleetconfig/v1alpha1"
	"github.com/spf13/cobra"
)

// applyFleetConfig loads the --fleet-config file into scanInfo, where a flag given on the command line wins over the file.
// It runs before validation, so a value from the file is checked exactly as the same flag would be.
func applyFleetConfig(cmd *cobra.Command, scanInfo *cautils.ScanInfo, path string) error {
	if path == "" {
		return nil
	}
	document, err := fleetconfigv1alpha1.LoadFile(path)
	if err != nil {
		return err
	}

	spec := document.Spec
	if spec.Contexts != nil && !commandFlagChanged(cmd, "kube-contexts") {
		scanInfo.KubeContexts = slices.Clone(*spec.Contexts)
	}
	if spec.Output != nil && !commandFlagChanged(cmd, "output") {
		scanInfo.Output = *spec.Output
	}
	if spec.FleetReport != nil && !commandFlagChanged(cmd, "fleet-report") {
		scanInfo.FleetReport = *spec.FleetReport
	}
	if spec.ReferenceCluster != nil && !commandFlagChanged(cmd, "reference-cluster") {
		scanInfo.ReferenceCluster = *spec.ReferenceCluster
	}
	if spec.Retries != nil && !commandFlagChanged(cmd, "retries") {
		scanInfo.KubeContextRetries = *spec.Retries
	}

	if len(scanInfo.KubeContexts) == 0 {
		return fmt.Errorf("--fleet-config %q names no contexts: set spec.contexts or pass --kube-contexts", path)
	}
	return nil
}

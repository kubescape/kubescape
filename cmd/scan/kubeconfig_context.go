package scan

import (
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// captureKubeconfigSelection snapshots the two CLI flags that select a
// kubeconfig context. It deliberately performs no file I/O here: persistent
// pre-run hooks also execute for offline and image-only scans.
func captureKubeconfigSelection(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
	scanInfo.SetKubeconfigSelection(
		commandStringFlag(cmd, "kubeconfig"),
		commandStringFlag(cmd, "kube-context"),
	)
}

func commandStringFlag(cmd *cobra.Command, name string) string {
	if cmd == nil {
		return ""
	}
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags()} {
		if flag := flags.Lookup(name); flag != nil {
			return flag.Value.String()
		}
	}
	return ""
}

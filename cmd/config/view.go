package config

import (
	"os"

	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getViewCmd(ks meta.IKubescape) *cobra.Command {
	viewCmd := &cobra.Command{
		Use:   "view",
		Short: "View cached configurations",
		Long:  `View cached Kubescape configuration in a human-readable text format, or render it as JSON or YAML.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFormat, _ := cmd.Flags().GetString("output")
			includeEmpty, _ := cmd.Flags().GetBool("include-empty")
			return ks.ViewCachedConfig(&v1.ViewConfig{Writer: os.Stdout, OutputFormat: outputFormat, IncludeEmpty: includeEmpty})
		},
	}

	viewCmd.Flags().StringP("output", "o", "text", "Output format: text, json, or yaml")
	viewCmd.Flags().BoolP("include-empty", "e", false, "Include empty values in the rendered output")
	return viewCmd
}

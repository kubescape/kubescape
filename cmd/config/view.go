package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getViewCmd(ks meta.IKubescape) *cobra.Command {
	viewCmd := &cobra.Command{
		Use:   "view [KEY]",
		Short: "View cached configurations",
		Long:  `View cached Kubescape configuration in a human-readable text format, or render it as JSON or YAML.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ks == nil {
				return errors.New("uninitialized kubescape interface")
			}
			outputFormat, _ := cmd.Flags().GetString("format")
			if !cmd.Flags().Changed("format") && cmd.Flags().Changed("output") {
				outputFormat, _ = cmd.Flags().GetString("output")
			}
			normalizedFormat := strings.ToLower(strings.TrimSpace(outputFormat))
			if normalizedFormat == "" {
				return fmt.Errorf("format cannot be empty, supported formats: text, json, yaml")
			}
			if normalizedFormat != "text" && normalizedFormat != "json" && normalizedFormat != "yaml" {
				return fmt.Errorf("unsupported format %q, supported formats: text, json, yaml", outputFormat)
			}
			includeEmpty, _ := cmd.Flags().GetBool("include-empty")

			key := ""
			if len(args) > 0 {
				key = args[0]
			}

			return ks.ViewCachedConfig(&v1.ViewConfig{
				Writer:       cmd.OutOrStdout(),
				OutputFormat: normalizedFormat,
				IncludeEmpty: includeEmpty,
				Key:          key,
			})
		},
	}

	viewCmd.Flags().StringP("format", "f", "text", "Output format: text, json, or yaml")
	viewCmd.Flags().StringP("output", "o", "text", "Output format: text, json, or yaml (alias for --format)")
	viewCmd.Flags().BoolP("include-empty", "e", false, "Include empty values in the rendered output")
	return viewCmd
}

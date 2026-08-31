package config

import (
	"os"

	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getValidateCmd(ks meta.IKubescape) *cobra.Command {
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate cached configurations",
		Long:  `Validate cached Kubescape configuration and render diagnostics as text, JSON, or YAML.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFormat, _ := cmd.Flags().GetString("format")
			if !cmd.Flags().Changed("format") && cmd.Flags().Changed("output") {
				outputFormat, _ = cmd.Flags().GetString("output")
			}
			profile, _ := cmd.Flags().GetString("profile")
			includeOK, _ := cmd.Flags().GetBool("include-ok")
			return ks.ValidateCachedConfig(&v1.ValidateConfig{Writer: os.Stdout, Format: outputFormat, Profile: profile, IncludeOK: includeOK})
		},
	}

	validateCmd.Flags().StringP("format", "f", "text", "Output format: text, json, or yaml")
	validateCmd.Flags().StringP("output", "o", "text", "Output format: text, json, or yaml (alias for --format)")
	validateCmd.Flags().String("profile", "cloud", "Validation profile: cloud or offline")
	validateCmd.Flags().Bool("include-ok", false, "Include passing validation checks in the rendered output")
	return validateCmd
}

package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getValidateCmd(ks meta.IKubescape) *cobra.Command {
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate cached configurations",
		Long:  `Validate cached Kubescape configuration and render diagnostics as text, JSON, or YAML.`,
		Args:  cobra.NoArgs,
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
			profile, _ := cmd.Flags().GetString("profile")
			includeOK, _ := cmd.Flags().GetBool("include-ok")
			return ks.ValidateCachedConfig(&v1.ValidateConfig{Writer: cmd.OutOrStdout(), Format: normalizedFormat, Profile: profile, IncludeOK: includeOK})
		},
	}

	validateCmd.Flags().StringP("format", "f", "text", "Output format: text, json, or yaml")
	validateCmd.Flags().StringP("output", "o", "text", "Output format: text, json, or yaml (alias for --format)")
	validateCmd.Flags().String("profile", "cloud", "Validation profile: cloud or offline")
	validateCmd.Flags().Bool("include-ok", false, "Include passing validation checks in the rendered output")
	return validateCmd
}

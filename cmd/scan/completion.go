package scan

import (
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/spf13/cobra"
)

// completeValues matches valid values against the typed prefix.
func completeValues(values []string) cobra.CompletionFunc {
	return func(
		cmd *cobra.Command,
		args []string,
		toComplete string,
	) ([]string, cobra.ShellCompDirective) {
		var matches []string

		for _, value := range values {
			if strings.HasPrefix(
				strings.ToLower(value),
				strings.ToLower(toComplete),
			) {
				if len(toComplete) <= len(value) {
					matches = append(matches, toComplete+value[len(toComplete):])
				}
			}
		}

		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeCommaSeparated completes comma-separated values without
// suggesting values that have already been selected.
func completeCommaSeparated(values []string) cobra.CompletionFunc {
	return func(
		cmd *cobra.Command,
		args []string,
		toComplete string,
	) ([]string, cobra.ShellCompDirective) {
		parts := strings.Split(toComplete, ",")
		prefix := strings.Join(parts[:len(parts)-1], ",")
		current := parts[len(parts)-1]

		selected := make(map[string]bool)

		for _, part := range parts[:len(parts)-1] {
			selected[strings.ToLower(strings.TrimSpace(part))] = true
		}

		var results []string

		for _, value := range values {
			if selected[strings.ToLower(value)] {
				continue
			}

			if !strings.HasPrefix(
				strings.ToLower(value),
				strings.ToLower(current),
			) {
				continue
			}

			if len(current) > len(value) {
				continue
			}

			candidate := current + value[len(current):]

			if len(parts) == 1 {
				results = append(results, candidate)
			} else {
				results = append(results, prefix+","+candidate)
			}
		}

		return results, cobra.ShellCompDirectiveNoSpace |
			cobra.ShellCompDirectiveNoFileComp
	}
}

// registerScanFlagCompletions registers value completion
// for supported scan flags.
func registerScanFlagCompletions(cmd *cobra.Command) {
	severityValues := []string{
		"low",
		"medium",
		"high",
		"critical",
	}

	completions := map[string][]string{
		"view":                        shared.SupportedViews,
		"severity-threshold":          severityValues,
		"baseline-severity-threshold": severityValues,
		"min-severity":                severityValues,
		"max-severity":                severityValues,
	}

	for flagName, values := range completions {
		if cmd.Flags().Lookup(flagName) == nil &&
			cmd.PersistentFlags().Lookup(flagName) == nil {
			continue
		}

		if err := cmd.RegisterFlagCompletionFunc(
			flagName,
			completeValues(values),
		); err != nil {
			panic(err)
		}

	}

	completeScanFormat := completeCommaSeparated(shared.ScanFormats)
	completeImageFormat := completeCommaSeparated(shared.ImageScanFormats)

	if err := cmd.RegisterFlagCompletionFunc(
		"format",
		func(currentCmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if currentCmd.Name() == "image" {
				return completeImageFormat(currentCmd, args, toComplete)
			}

			return completeScanFormat(currentCmd, args, toComplete)
		},
	); err != nil {
		panic(err)
	}
}

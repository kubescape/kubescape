package shared

import (
	"strings"

	"github.com/spf13/cobra"
)

// SeverityLevels lists the severity threshold values accepted by scan and diff flags.
var SeverityLevels = []string{
	"low",
	"medium",
	"high",
	"critical",
}

// CompleteValues returns a Cobra completion function that matches valid values
// case-insensitively against the typed prefix while preserving the typed casing.
func CompleteValues(values []string) cobra.CompletionFunc {
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

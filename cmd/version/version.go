package version

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func GetVersionCmd(ks meta.IKubescape, version, commit, date string) *cobra.Command {
	var outputFormat string

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Get current version",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch outputFormat {
			case "json":
				info := versionInfo{
					Version: version,
					Commit:  commit,
					Date:    date,
				}
				b, err := json.Marshal(info)
				if err != nil {
					return fmt.Errorf("failed to marshal version info: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			case "yaml":
				info := versionInfo{
					Version: version,
					Commit:  commit,
					Date:    date,
				}
				b, err := yaml.Marshal(info)
				if err != nil {
					return fmt.Errorf("failed to marshal version info: %w", err)
				}
				_, err = fmt.Fprint(cmd.OutOrStdout(), string(b))
				return err
			case "text":
				v := versioncheck.NewIVersionCheckHandler(ks.Context())
				_ = v.CheckLatestVersion(ks.Context(), versioncheck.NewVersionCheckRequest("", version, "", "", "version", nil))

				out := cmd.OutOrStdout()
				colored := shouldColor(out)
				chalk := colorBuilder(colored)

				verStr := version
				commitStr := commit
				dateStr := date

				if colored {
					if version != "" {
						verStr = chalk.WithBrightGreen().Bold(version)
					}
					if commit != "" {
						commitStr = chalk.BrightCyan(commit)
					}
					if date != "" {
						dateStr = chalk.BrightWhite(date)
					}
				}

				if _, err := fmt.Fprintf(out, "Your current version is: %s\n", verStr); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(out, "Build commit: %s\n", commitStr); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "Build date: %s\n", dateStr)
				return err
			default:
				return fmt.Errorf("unsupported format %q, supported: text, json, yaml", outputFormat)
			}
		},
	}

	versionCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", `Output format. Supported: "text", "json", "yaml"`)

	return versionCmd
}

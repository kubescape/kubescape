package version

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/spf13/cobra"
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
			case "text":
				v := versioncheck.NewIVersionCheckHandler(ks.Context())
				_ = v.CheckLatestVersion(ks.Context(), versioncheck.NewVersionCheckRequest("", version, "", "", "version", nil))

				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Your current version is: %s\n", version); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Build commit: %s\n", commit); err != nil {
					return err
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Build date: %s\n", date)
				return err
			default:
				return fmt.Errorf("unsupported format %q, supported: text, json", outputFormat)
			}
		},
	}

	versionCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", `Output format. Supported: "text", "json"`)

	return versionCmd
}

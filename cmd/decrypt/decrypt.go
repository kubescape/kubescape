package decrypt

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
)

func GetDecryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <report.json>",
		Short: "Decrypt encrypted Kubescape reports",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf(
					"failed to read report %q: %w",
					args[0],
					err,
				)
			}

			var report reporthandlingv2.PostureReport

			if err := json.Unmarshal(data, &report); err != nil {
				return fmt.Errorf(
					"failed to parse report: %w",
					err,
				)
			}

			if err := reportcrypto.DecryptMetadataFromEnv(
				&report.Metadata,
			); err != nil {
				return err
			}

			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")

			return encoder.Encode(report)
		},
	}
}

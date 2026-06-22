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

			var report map[string]json.RawMessage

			if err := json.Unmarshal(
				data,
				&report,
			); err != nil {
				return fmt.Errorf(
					"failed to parse report: %w",
					err,
				)
			}

			metadataRaw, ok := report["metadata"]
			if !ok {
				return fmt.Errorf(
					"report metadata not found",
				)
			}

			var metadata reporthandlingv2.Metadata

			if err := json.Unmarshal(
				metadataRaw,
				&metadata,
			); err != nil {
				return fmt.Errorf(
					"failed to parse metadata: %w",
					err,
				)
			}

			if err := reportcrypto.DecryptMetadataFromEnv(
				&metadata,
			); err != nil {
				return err
			}

			updatedMetadata, err := json.Marshal(
				metadata,
			)
			if err != nil {
				return fmt.Errorf(
					"failed to marshal metadata: %w",
					err,
				)
			}

			report["metadata"] = updatedMetadata

			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")

			return encoder.Encode(report)
		},
	}
}

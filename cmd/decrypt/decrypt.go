package decrypt

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/spf13/cobra"
)

var decryptCmdExamples = `
  # The key is used as raw bytes and must be exactly 32 characters long.
  # Note: openssl rand -base64 32 (44 chars) and openssl rand -hex 32 (64 chars)
  # are NOT valid because they exceed 32 bytes when passed as raw text.
  export KUBESCAPE_MASTER_KEY="01234567890123456789012345678901"

  # Decrypt an encrypted report
  kubescape decrypt encrypted-report.json

  # Save the decrypted report to a file
  kubescape decrypt encrypted-report.json > decrypted-report.json
`

func GetDecryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <report.json>",
		Short: "Decrypt a report produced by kubescape scan --encrypt",
		Long: `Decrypt all encrypted report fields using KUBESCAPE_MASTER_KEY.

The command restores metadata, resources, result raw resources, resource
labels, and resource ID references. The decrypted report is written to
standard output and can be redirected to a file.`,
		Example: decryptCmdExamples,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read report %q: %w", args[0], err)
			}

			decrypted, err := reportcrypto.DecryptReportFromEnv(data)
			if err != nil {
				return err
			}

			if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(decrypted)); err != nil {
				return fmt.Errorf("failed to write decrypted report: %w", err)
			}

			return nil
		},
	}
}

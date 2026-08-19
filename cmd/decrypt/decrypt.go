package decrypt

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/spf13/cobra"
)

var decryptCmdExamples = `
  # Supply the same passphrase that encrypted the report. Hex-encoded key
  # material goes in KUBESCAPE_MASTER_KEY_HEX instead.
  export KUBESCAPE_MASTER_KEY="$(cat master-key.txt)"

  # Decrypt an encrypted report
  kubescape decrypt encrypted-report.json

  # Save the decrypted report to a file
  kubescape decrypt encrypted-report.json > decrypted-report.json
`

func GetDecryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "decrypt <report.json>",
		Short:        "Decrypt a report produced by kubescape scan --encrypt",
		SilenceUsage: true,
		Long: `Decrypt all encrypted report fields using KUBESCAPE_MASTER_KEY
(or KUBESCAPE_MASTER_KEY_HEX).

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

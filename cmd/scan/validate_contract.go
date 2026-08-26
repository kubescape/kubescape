package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/spf13/cobra"
)

func getValidateContractCmd(scanInfo *cautils.ScanInfo) *cobra.Command {
	var contractName string
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "validate-contract <file>",
		Short: "Validate and select a repository scan contract without running a scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := contractv1alpha1.LoadFile(args[0], contractv1alpha1.LoadOptions{
				ContractName:        contractName,
				RunningVersion:      versioncheck.BuildNumber,
				SupportedFormats:    shared.ScanFormats,
				SupportedSeverities: reporthandlingapis.GetSupportedSeverities(),
			})
			if err != nil {
				return err
			}

			var output []byte
			switch outputFormat {
			case "text":
				output = []byte(fmt.Sprintf("Scan contract %q is valid\nSelected contract: %s\nContract digest: %s\n", selected.Metadata.Name, selected.ContractName, selected.ContractDigest))
			case "json":
				output, err = json.MarshalIndent(selected, "", "  ")
				if err != nil {
					return fmt.Errorf("encode validated contract: %w", err)
				}
				output = append(output, '\n')
			default:
				return fmt.Errorf("unsupported format %q, supported: text, json", outputFormat)
			}

			if scanInfo.Output != "" {
				if err := os.WriteFile(scanInfo.Output, output, 0o600); err != nil {
					return fmt.Errorf("write validation output: %w", err)
				}
				return nil
			}
			_, err = cmd.OutOrStdout().Write(output)
			return err
		},
	}

	cmd.Flags().StringVar(&contractName, "contract", "", "Named contract to validate; defaults to spec.defaultContract")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", `Output format. Supported: "text", "json"`)
	cmd.Example = strings.Join([]string{
		"  kubescape scan validate-contract kubescape.yaml",
		"  kubescape scan validate-contract kubescape.yaml --contract ci --format json",
	}, "\n")
	return cmd
}

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/spf13/cobra"
)

const (
	validateContractFormatText  = "text"
	validateContractFormatJSON  = "json"
	validateContractFormatSARIF = "sarif"
)

func getValidateContractCmd(scanInfo *cautils.ScanInfo) *cobra.Command {
	var contractName string
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "validate-contract <file>",
		Short: "Validate and select a repository scan contract without running a scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, validationErr := contractv1alpha1.LoadFile(args[0], contractv1alpha1.LoadOptions{
				ContractName:        contractName,
				RunningVersion:      versioncheck.BuildNumber,
				SupportedFormats:    shared.ScanFormats,
				SupportedSeverities: reporthandlingapis.GetSupportedSeverities(),
			})
			if validationErr != nil && outputFormat != validateContractFormatSARIF {
				return validationErr
			}

			var output []byte
			var err error
			switch outputFormat {
			case validateContractFormatText:
				output = []byte(fmt.Sprintf("Scan contract %q is valid\nSelected contract: %s\nContract digest: %s\n", selected.Metadata.Name, selected.ContractName, selected.ContractDigest))
			case validateContractFormatJSON:
				output, err = json.MarshalIndent(selected, "", "  ")
				if err != nil {
					return fmt.Errorf("encode validated contract: %w", err)
				}
				output = append(output, '\n')
			case validateContractFormatSARIF:
				output, err = validateContractSARIF(args[0], selected, validationErr)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported format %q, supported: text, json, sarif", outputFormat)
			}

			if scanInfo.Output != "" {
				if err := os.WriteFile(scanInfo.Output, output, 0o600); err != nil {
					return fmt.Errorf("write validation output: %w", err)
				}
				if outputFormat == validateContractFormatSARIF && validationErr != nil {
					cmd.SilenceUsage = true
					cmd.SilenceErrors = true
					return validationErr
				}
				return nil
			}
			if _, err = cmd.OutOrStdout().Write(output); err != nil {
				return err
			}
			if outputFormat == validateContractFormatSARIF && validationErr != nil {
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				return validationErr
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&contractName, "contract", "", "Named contract to validate; defaults to spec.defaultContract")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", `Output format. Supported: "text", "json", "sarif"`)
	cmd.Example = strings.Join([]string{
		"  kubescape scan validate-contract kubescape.yaml",
		"  kubescape scan validate-contract kubescape.yaml --contract ci --format json",
		"  kubescape scan validate-contract kubescape.yaml --format sarif",
	}, "\n")
	return cmd
}

type validateContractSARIFReport struct {
	Version string                     `json:"version"`
	Schema  string                     `json:"$schema"`
	Runs    []validateContractSARIFRun `json:"runs"`
}

type validateContractSARIFRun struct {
	Tool        validateContractSARIFTool         `json:"tool"`
	Invocations []validateContractSARIFInvocation `json:"invocations"`
	Artifacts   []validateContractSARIFArtifact   `json:"artifacts,omitempty"`
	Results     []validateContractSARIFResult     `json:"results"`
}

type validateContractSARIFTool struct {
	Driver validateContractSARIFDriver `json:"driver"`
}

type validateContractSARIFDriver struct {
	Name            string                      `json:"name"`
	InformationURI  string                      `json:"informationUri,omitempty"`
	SemanticVersion string                      `json:"semanticVersion,omitempty"`
	Rules           []validateContractSARIFRule `json:"rules"`
}

type validateContractSARIFRule struct {
	ID               string                       `json:"id"`
	Name             string                       `json:"name"`
	ShortDescription validateContractSARIFMessage `json:"shortDescription"`
	FullDescription  validateContractSARIFMessage `json:"fullDescription"`
	HelpURI          string                       `json:"helpUri,omitempty"`
}

type validateContractSARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
	ExitCode            int  `json:"exitCode"`
}

type validateContractSARIFArtifact struct {
	Location validateContractSARIFArtifactLocation `json:"location"`
}

type validateContractSARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type validateContractSARIFResult struct {
	RuleID    string                          `json:"ruleId"`
	Level     string                          `json:"level"`
	Message   validateContractSARIFMessage    `json:"message"`
	Locations []validateContractSARIFLocation `json:"locations,omitempty"`
}

type validateContractSARIFLocation struct {
	PhysicalLocation validateContractSARIFPhysicalLocation `json:"physicalLocation"`
}

type validateContractSARIFPhysicalLocation struct {
	ArtifactLocation validateContractSARIFArtifactLocation `json:"artifactLocation"`
	Region           validateContractSARIFRegion           `json:"region,omitempty"`
}

type validateContractSARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type validateContractSARIFMessage struct {
	Text string `json:"text"`
}

func validateContractSARIF(path string, selected *contractv1alpha1.SelectedContract, validationErr error) ([]byte, error) {
	report := validateContractSARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []validateContractSARIFRun{
			{
				Tool: validateContractSARIFTool{
					Driver: validateContractSARIFDriver{
						Name:           "Kubescape",
						InformationURI: "https://kubescape.io",
						Rules:          validateContractSARIFRules(),
					},
				},
				Invocations: []validateContractSARIFInvocation{
					{
						ExecutionSuccessful: validationErr == nil,
						ExitCode:            validateContractSARIFExitCode(validationErr),
					},
				},
				Artifacts: []validateContractSARIFArtifact{
					{Location: validateContractSARIFArtifactLocation{URI: validateContractArtifactURI(path)}},
				},
				Results: validateContractSARIFResults(path, validationErr),
			},
		},
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode validate-contract SARIF: %w", err)
	}
	return append(out, '\n'), nil
}

func validateContractSARIFRules() []validateContractSARIFRule {
	return []validateContractSARIFRule{
		{
			ID:               "kubescape.scan-contract.valid",
			Name:             "Scan contract validation",
			ShortDescription: validateContractSARIFMessage{Text: "Validate a Kubescape scan contract"},
			FullDescription:  validateContractSARIFMessage{Text: "Checks that a repository scan contract is syntactically valid and compatible with this Kubescape version."},
		},
	}
}

func validateContractSARIFResults(path string, validationErr error) []validateContractSARIFResult {
	if validationErr != nil {
		return []validateContractSARIFResult{
			{
				RuleID:  "kubescape.scan-contract.valid",
				Level:   "error",
				Message: validateContractSARIFMessage{Text: validationErr.Error()},
				Locations: []validateContractSARIFLocation{
					{
						PhysicalLocation: validateContractSARIFPhysicalLocation{
							ArtifactLocation: validateContractSARIFArtifactLocation{URI: validateContractArtifactURI(path)},
							Region:           validateContractSARIFRegion{StartLine: 1},
						},
					},
				},
			},
		}
	}
	return []validateContractSARIFResult{}
}

func validateContractSARIFExitCode(validationErr error) int {
	if validationErr != nil {
		return 1
	}
	return 0
}

func validateContractArtifactURI(path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		cwd, cwdErr := os.Getwd()
		if cwdErr == nil {
			base := validateContractCleanPath(cwd)
			target := validateContractCleanPath(path)
			relative, err := filepath.Rel(base, target)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				return filepath.ToSlash(relative)
			}
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(path))
	return cleaned
}

func validateContractCleanPath(path string) string {
	cleaned := filepath.Clean(path)
	if evaluated, err := filepath.EvalSymlinks(cleaned); err == nil {
		return evaluated
	}
	return cleaned
}

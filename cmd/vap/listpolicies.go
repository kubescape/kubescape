package vap

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

const (
	formatPretty = "pretty-print"
	formatJSON   = "json"
	formatYAML   = "yaml"
	formatCSV    = "csv"
)

var listPoliciesFormats = []string{formatPretty, formatJSON, formatYAML, formatCSV}

type policyListEntry struct {
	Policy           string   `json:"policy"`
	ControlID        string   `json:"controlID,omitempty"`
	TakesParams      bool     `json:"takesParams"`
	FailurePolicy    string   `json:"failurePolicy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	DuplicateName    bool     `json:"duplicateName,omitempty"`
	DuplicateControl bool     `json:"duplicateControl,omitempty"`
}

func getListPoliciesCmd() *cobra.Command {
	var format string
	var controlsOnly bool
	var outputFile string

	cmd := &cobra.Command{
		Use:   "list-policies",
		Short: "List the ValidatingAdmissionPolicies in the embedded library",
		Long:  `Lists every policy in the CEL admission policy library embedded in this binary, with the Kubescape control it implements. Use the control IDs with 'vap create-policy-binding --control' and the policy names with '--policy'.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			normalizedFormat, err := validateListPoliciesFormat(format)
			if err != nil {
				return err
			}
			var rendered bytes.Buffer
			if err := runListPolicies(&rendered, normalizedFormat, controlsOnly); err != nil {
				return err
			}
			if outputFile != "" {
				return writeOutput(rendered.String(), outputFile)
			}
			_, err = cmd.OutOrStdout().Write(rendered.Bytes())
			return err
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", formatPretty, fmt.Sprintf("output format. supported: %s", strings.Join(quoted(listPoliciesFormats), "/")))
	cmd.Flags().BoolVar(&controlsOnly, "controls-only", false, "Only list policies that implement a Kubescape control")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	return cmd
}

func validateListPoliciesFormat(format string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(format))
	supported := strings.Join(quoted(listPoliciesFormats), "/")
	if trimmed == "" {
		return "", fmt.Errorf("format cannot be empty, supported formats: %s", supported)
	}
	if !slices.Contains(listPoliciesFormats, trimmed) {
		return "", fmt.Errorf("invalid format %q, supported formats: %s", format, supported)
	}
	return trimmed, nil
}

func runListPolicies(out io.Writer, format string, controlsOnly bool) error {
	normalizedFormat, err := validateListPoliciesFormat(format)
	if err != nil {
		return err
	}

	policies, err := cel.ListPolicies()
	if err != nil {
		return fmt.Errorf("read embedded policy library: %w", err)
	}

	entries := make([]policyListEntry, 0, len(policies))
	for _, policy := range policies {
		if controlsOnly && policy.ControlID == "" {
			continue
		}
		entries = append(entries, policyListEntry{
			Policy:           policy.PolicyName,
			ControlID:        policy.ControlID,
			TakesParams:      policy.TakesParams,
			FailurePolicy:    policy.FailurePolicy,
			Resources:        policy.Resources,
			DuplicateName:    policy.DuplicateName,
			DuplicateControl: policy.DuplicateControl,
		})
	}

	switch normalizedFormat {
	case formatPretty:
		prettyPrintPolicies(out, entries)
	case formatJSON:
		encoded, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("encode policies: %w", err)
		}
		fmt.Fprintf(out, "%s\n", encoded)
	case formatYAML:
		encoded, err := yaml.Marshal(entries)
		if err != nil {
			return fmt.Errorf("encode policies: %w", err)
		}
		fmt.Fprintf(out, "%s", encoded)
	case formatCSV:
		return csvPolicies(out, entries)
	default:
		return fmt.Errorf("invalid format %q, supported formats: %s", format, strings.Join(quoted(listPoliciesFormats), "/"))
	}

	return nil
}

func prettyPrintPolicies(out io.Writer, entries []policyListEntry) {
	policyTable := table.NewWriter()
	policyTable.SetOutputMirror(out)

	policyTable.Style().Options.SeparateHeader = true
	policyTable.Style().Options.SeparateRows = true
	policyTable.Style().Format.HeaderAlign = text.AlignLeft
	policyTable.Style().Format.Header = text.FormatDefault
	policyTable.Style().Box = table.StyleBoxRounded

	policyTable.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, WidthMax: 48},
		{Number: 5, WidthMax: 40},
	})

	policyTable.AppendHeader(table.Row{"Control ID", "Policy", "Params", "On error", "Resources"})
	for _, entry := range entries {
		policyTable.AppendRow(table.Row{
			controlDisplayID(entry),
			policyDisplayName(entry),
			yesNo(entry.TakesParams),
			orDash(entry.FailurePolicy),
			orDash(strings.Join(entry.Resources, ", ")),
		})
	}

	policyTable.Render()
}

// csvFormulaPrefixes contains the characters spreadsheets treat as the start of
// an executable formula or command payload if placed at the start of a cell.
// Leading whitespace is included too, since a cell starting with a newline or
// carriage return can still execute a formula on its first non-blank line.
const csvFormulaPrefixes = "=+-@\t\r\n"

// csvSafeCell neutralizes a cell against spreadsheet formula injection (CWE-1236)
// by prepending a single quote, the standard mitigation: spreadsheets treat a
// leading apostrophe as literal text and do not execute or display it, while
// other CSV consumers see an inert string.
func csvSafeCell(cell string) string {
	if cell == "" {
		return cell
	}
	if strings.ContainsRune(csvFormulaPrefixes, rune(cell[0])) {
		return "'" + cell
	}
	return cell
}

// csvSafeRow applies csvSafeCell across every cell of a CSV row.
func csvSafeRow(row []string) []string {
	for i := range row {
		row[i] = csvSafeCell(row[i])
	}
	return row
}

func csvPolicies(out io.Writer, entries []policyListEntry) error {
	writer := csv.NewWriter(out)
	if err := writer.Write([]string{"controlID", "policy", "takesParams", "failurePolicy", "resources", "duplicateName", "duplicateControl"}); err != nil {
		return fmt.Errorf("write csv output: %w", err)
	}
	for _, entry := range entries {
		record := []string{
			entry.ControlID,
			entry.Policy,
			strconv.FormatBool(entry.TakesParams),
			entry.FailurePolicy,
			strings.Join(entry.Resources, ";"),
			strconv.FormatBool(entry.DuplicateName),
			strconv.FormatBool(entry.DuplicateControl),
		}
		if err := writer.Write(csvSafeRow(record)); err != nil {
			return fmt.Errorf("write csv output: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("write csv output: %w", err)
	}
	return nil
}

func policyDisplayName(entry policyListEntry) string {
	if entry.DuplicateName {
		return entry.Policy + " (duplicate name)"
	}
	return entry.Policy
}

func controlDisplayID(entry policyListEntry) string {
	if entry.DuplicateControl {
		return entry.ControlID + " (duplicate)"
	}
	return orDash(entry.ControlID)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func quoted(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, "'"+v+"'")
	}
	return out
}

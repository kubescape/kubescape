package core

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/maruel/natural"
	"sigs.k8s.io/yaml"
)

// listFunc handles targets whose output is a flat []string (frameworks, exceptions).
// "controls" is handled separately via listControls because it produces typed structs.
var listFunc = map[string]func(context.Context, *metav1.ListPolicies) ([]string, error){
	"frameworks": listFrameworks,
	"exceptions": listExceptions,
}

var listFormatFunc = map[string]func(context.Context, string, []string){
	"pretty-print": prettyPrintListFormat,
	"json":         jsonListFormat,
	"yaml":         yamlListFormat,
	"csv":          csvListFormat,
}

func ListSupportActions() []string {
	commands := []string{"controls"}
	for key := range listFunc {
		commands = append(commands, key)
	}

	sort.Strings(commands)
	return commands
}

func (ks *Kubescape) List(listPolicies *metav1.ListPolicies) (*metav1.ListResult, error) {
	if listPolicies.Target == "controls" {
		entries, err := listControls(ks.Context(), listPolicies)
		if err != nil {
			return nil, err
		}
		entries = naturalSortControls(entries)
		return &metav1.ListResult{Controls: entries}, nil
	}

	if policyListerFunc, ok := listFunc[listPolicies.Target]; ok {
		policies, err := policyListerFunc(ks.Context(), listPolicies)
		if err != nil {
			return nil, err
		}
		policies = naturalSortPolicies(policies)
		return &metav1.ListResult{Names: policies}, nil
	}
	return nil, fmt.Errorf("unknown command to list")
}

// PrintListResult writes a ListResult to the configured output using the
// requested target and format. It is the caller side of Kubescape.List.
func PrintListResult(ctx context.Context, result *metav1.ListResult, target, format string) error {
	if result == nil {
		return nil
	}

	switch target {
	case "controls":
		switch format {
		case "pretty-print":
			prettyPrintControls(ctx, result.Controls)
		case "json":
			jsonControlsFormat(result.Controls)
		case "yaml":
			yamlControlsFormat(result.Controls)
		case "csv":
			csvControlsFormat(result.Controls)
		default:
			return fmt.Errorf("invalid format \"%s\", supported formats: 'pretty-print'/'json'/'yaml'/'csv'", format)
		}
	case "frameworks", "exceptions":
		if listFormatFunction, ok := listFormatFunc[format]; ok {
			listFormatFunction(ctx, target, result.Names)
		} else {
			return fmt.Errorf("invalid format \"%s\", supported formats: 'pretty-print'/'json'/'yaml'/'csv'", format)
		}
	default:
		return fmt.Errorf("invalid target %q, supported targets: 'controls'/'frameworks'/'exceptions'", target)
	}
	return nil
}
func naturalSortPolicies(policies []string) []string {
	sort.Slice(policies, func(i, j int) bool {
		return natural.Less(policies[i], policies[j])
	})
	return policies
}

func naturalSortControls(entries []metav1.ControlListEntry) []metav1.ControlListEntry {
	sort.Slice(entries, func(i, j int) bool {
		return natural.Less(entries[i].ID, entries[j].ID)
	})
	return entries
}

func listFrameworks(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := cautils.GetTenantConfig(ctx, listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface
	policyGetter, err := getPolicyGetter(ctx, nil, tenant.GetAccountID(), true, nil, false)
	if err != nil {
		return nil, err
	}

	return listFrameworksNames(policyGetter), nil
}

func listControls(ctx context.Context, listPolicies *metav1.ListPolicies) ([]metav1.ControlListEntry, error) {
	tenant := cautils.GetTenantConfig(ctx, listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface

	policyGetter, err := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, nil, false)
	if err != nil {
		return nil, err
	}
	pipes, err := policyGetter.ListControls()
	if err != nil {
		return nil, err
	}
	entries := make([]metav1.ControlListEntry, 0, len(pipes))
	for _, pipe := range pipes {
		entries = append(entries, parseControlEntry(pipe))
	}
	return entries, nil
}

// parseControlEntry converts a pipe-delimited "id|name|fw1, fw2" string into a ControlListEntry.
func parseControlEntry(pipe string) metav1.ControlListEntry {
	entry := metav1.ControlListEntry{Frameworks: []string{}}
	if pipe == "" {
		return entry
	}

	before, after, ok := strings.Cut(pipe, "|")
	if !ok {
		entry.ID = pipe
		return entry
	}
	entry.ID = before

	rest := after
	last := strings.LastIndex(rest, "|")
	if last == -1 {
		entry.Name = rest
		return entry
	}

	entry.Name = rest[:last]
	frameworksRaw := rest[last+1:]
	if frameworksRaw != "" {
		for fw := range strings.SplitSeq(frameworksRaw, ",") {
			if fw = strings.TrimSpace(fw); fw != "" {
				entry.Frameworks = append(entry.Frameworks, fw)
			}
		}
	}
	return entry
}

func listExceptions(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	// load tenant metav1
	tenant := cautils.GetTenantConfig(ctx, listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi())

	var exceptionsNames []string
	ksCloudAPI, _, err := getExceptionsGetter(ctx, "", tenant.GetAccountID(), nil, false)
	if err != nil {
		return exceptionsNames, err
	}
	exceptions, err := ksCloudAPI.GetExceptions(ctx, "")
	if err != nil {
		return exceptionsNames, err
	}
	for i := range exceptions {
		exceptionsNames = append(exceptionsNames, exceptions[i].Name)
	}
	return exceptionsNames, nil
}

func prettyPrintListFormat(ctx context.Context, targetPolicy string, policies []string) {
	policyTable := table.NewWriter()
	policyTable.SetOutputMirror(printer.GetWriter(ctx, ""))

	header := fmt.Sprintf("Supported %s", targetPolicy)
	policyTable.AppendHeader(table.Row{header})
	policyTable.Style().Options.SeparateHeader = true
	policyTable.Style().Options.SeparateRows = true
	policyTable.Style().Format.HeaderAlign = text.AlignLeft
	policyTable.Style().Format.Header = text.FormatDefault
	policyTable.Style().Format.RowAlign = text.AlignCenter
	policyTable.Style().Box = table.StyleBoxRounded

	policyTable.AppendRows(generatePolicyRows(policies))
	policyTable.Render()
}

func jsonListFormat(_ context.Context, _ string, policies []string) {
	j, _ := json.MarshalIndent(policies, "", "  ")

	fmt.Printf("%s\n", j)
}

func jsonControlsFormat(entries []metav1.ControlListEntry) {
	j, _ := json.MarshalIndent(entries, "", "  ")

	fmt.Printf("%s\n", j)
}

func yamlListFormat(_ context.Context, _ string, policies []string) {
	y, err := yaml.Marshal(policies)
	if err != nil {
		return
	}

	fmt.Printf("%s\n", y)
}

func yamlControlsFormat(entries []metav1.ControlListEntry) {
	y, err := yaml.Marshal(entries)
	if err != nil {
		return
	}

	fmt.Printf("%s\n", y)
}

func csvListFormat(_ context.Context, _ string, policies []string) {
	writer := csv.NewWriter(os.Stdout)
	_ = writer.Write([]string{"name"})
	for _, policy := range policies {
		_ = writer.Write([]string{policy})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write csv output: %v\n", err)
	}
}

func csvControlsFormat(entries []metav1.ControlListEntry) {
	writer := csv.NewWriter(os.Stdout)
	_ = writer.Write([]string{"id", "name", "frameworks"})
	for _, entry := range entries {
		frameworks := strings.Join(entry.Frameworks, ";")
		_ = writer.Write([]string{entry.ID, entry.Name, frameworks})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write csv output: %v\n", err)
	}
}

func prettyPrintControls(ctx context.Context, entries []metav1.ControlListEntry) {
	controlsTable := table.NewWriter()
	controlsTable.SetOutputMirror(printer.GetWriter(ctx, ""))

	controlsTable.Style().Options.SeparateHeader = true
	controlsTable.Style().Options.SeparateRows = true
	controlsTable.Style().Format.HeaderAlign = text.AlignLeft
	controlsTable.Style().Format.Header = text.FormatDefault
	controlsTable.Style().Box = table.StyleBoxRounded
	controlsTable.SetColumnConfigs([]table.ColumnConfig{{Number: 1, Align: text.AlignRight}})

	controlRows := generateControlRows(entries)

	short := utils.CheckShortTerminalWidth(controlRows, table.Row{"Control ID", "Control name", "Docs", "Frameworks"})
	if short {
		controlsTable.AppendHeader(table.Row{"Controls"})
		controlRows = shortFormatControlRows(controlRows)
	} else {
		controlsTable.AppendHeader(table.Row{"Control ID", "Control name", "Docs", "Frameworks"})
	}

	controlsTable.AppendRows(controlRows)
	controlsTable.Render()
}

func generateControlRows(entries []metav1.ControlListEntry) []table.Row {
	rows := make([]table.Row, 0, len(entries))

	for _, entry := range entries {
		docs := cautils.GetControlLink(entry.ID)
		frameworks := strings.Join(entry.Frameworks, "\n")
		rows = append(rows, table.Row{entry.ID, entry.Name, docs, frameworks})
	}

	return rows
}

func generatePolicyRows(policies []string) []table.Row {
	rows := make([]table.Row, 0, len(policies))

	for _, policy := range policies {
		rows = append(rows, table.Row{policy})
	}
	return rows
}

func shortFormatControlRows(controlRows []table.Row) []table.Row {
	rows := make([]table.Row, 0, len(controlRows))
	for _, controlRow := range controlRows {
		rows = append(rows, table.Row{fmt.Sprintf("Control ID"+strings.Repeat(" ", 3)+": %+v\nControl Name"+strings.Repeat(" ", 1)+": %+v\nDocs"+strings.Repeat(" ", 9)+": %+v\nFrameworks"+strings.Repeat(" ", 3)+": %+v", controlRow[0], controlRow[1], controlRow[2], strings.ReplaceAll(controlRow[3].(string), "\n", " "))})
	}
	return rows
}

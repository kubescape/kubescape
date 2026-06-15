package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/maruel/natural"
)

// listFunc handles targets whose output is a flat []string (frameworks, exceptions).
// "controls" is handled separately via listAndFormatControls because it produces typed structs.
var listFunc = map[string]func(context.Context, *metav1.ListPolicies) ([]string, error){
	"frameworks": listFrameworks,
	"exceptions": listExceptions,
}

var listFormatFunc = map[string]func(context.Context, string, []string){
	"pretty-print": prettyPrintListFormat,
	"json":         jsonListFormat,
}

func ListSupportActions() []string {
	commands := []string{"controls"}
	for key := range listFunc {
		commands = append(commands, key)
	}

	sort.Strings(commands)
	return commands
}

func (ks *Kubescape) List(listPolicies *metav1.ListPolicies) error {
	if listPolicies.Target == "controls" {
		return ks.listAndFormatControls(listPolicies)
	}

	if policyListerFunc, ok := listFunc[listPolicies.Target]; ok {
		policies, err := policyListerFunc(ks.Context(), listPolicies)
		if err != nil {
			return err
		}
		policies = naturalSortPolicies(policies)

		if listFormatFunction, ok := listFormatFunc[listPolicies.Format]; ok {
			listFormatFunction(ks.Context(), listPolicies.Target, policies)
		} else {
			return fmt.Errorf("invalid format \"%s\", supported formats: 'pretty-print'/'json' ", listPolicies.Format)
		}

		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func (ks *Kubescape) listAndFormatControls(listPolicies *metav1.ListPolicies) error {
	entries, err := listControls(ks.Context(), listPolicies)
	if err != nil {
		return err
	}
	entries = naturalSortControls(entries)

	switch listPolicies.Format {
	case "pretty-print":
		prettyPrintControls(ks.Context(), entries)
	case "json":
		jsonControlsFormat(entries)
	default:
		return fmt.Errorf("invalid format \"%s\", supported formats: 'pretty-print'/'json'", listPolicies.Format)
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
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface
	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), true, nil)

	return listFrameworksNames(policyGetter), nil
}

func listControls(ctx context.Context, listPolicies *metav1.ListPolicies) ([]metav1.ControlListEntry, error) {
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface

	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, nil)
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

// parseControlEntry converts a pipe-delimited "id|name|fw1, fw2" string from
// IPolicyGetter.ListControls into a typed ControlListEntry.
func parseControlEntry(pipe string) metav1.ControlListEntry {
	parts := strings.SplitN(pipe, "|", 3)
	entry := metav1.ControlListEntry{Frameworks: []string{}}
	if len(parts) > 0 {
		entry.ID = parts[0]
	}
	if len(parts) > 1 {
		entry.Name = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		for _, fw := range strings.Split(parts[2], ", ") {
			if fw = strings.TrimSpace(fw); fw != "" {
				entry.Frameworks = append(entry.Frameworks, fw)
			}
		}
	}
	return entry
}

func listExceptions(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	// load tenant metav1
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi())

	var exceptionsNames []string
	ksCloudAPI := getExceptionsGetter(ctx, "", tenant.GetAccountID(), nil)
	exceptions, err := ksCloudAPI.GetExceptions("")
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

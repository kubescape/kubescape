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
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
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
	commands := []string{"controls", "controls-config"}
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

	if listPolicies.Target == "controls-config" {
		entries, err := listControlsConfig(ks.Context(), listPolicies)
		if err != nil {
			return nil, err
		}
		return &metav1.ListResult{ControlsConfig: entries}, nil
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
	case "controls-config":
		switch format {
		case "pretty-print":
			prettyPrintControlsConfig(ctx, result.ControlsConfig)
		case "json":
			jsonControlsConfigFormat(result.ControlsConfig)
		case "yaml":
			yamlControlsConfigFormat(result.ControlsConfig)
		case "csv":
			csvControlsConfigFormat(result.ControlsConfig)
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
		return fmt.Errorf("invalid target %q, supported targets: 'controls'/'controls-config'/'frameworks'/'exceptions'", target)
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

// listControlsConfig resolves the configurable inputs a scan evaluates controls
// against, from the same sources a scan would use, and pairs each one with the
// controls that read it.
func listControlsConfig(ctx context.Context, listPolicies *metav1.ListPolicies) ([]metav1.ControlConfigEntry, error) {
	k8s := getKubernetesApi()
	tenant := cautils.GetTenantConfig(ctx, listPolicies.AccountID, listPolicies.AccessKey, "", "", k8s)

	// Both getters fall back to the released regolibrary, and each builds its own
	// downloader when given none, which fetches the release twice.
	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy()

	// A cluster scan prefers the ControlInput CRD over the released defaults, so
	// resolving without it would report values the next scan will not use.
	configGetter, _, err := getConfigInputsGetterForTarget(ctx, listPolicies.ControlsInputs, tenant.GetAccountID(), downloadReleasedPolicy, k8s != nil, false, k8s)
	if err != nil {
		return nil, err
	}
	policyGetter, err := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, downloadReleasedPolicy, false)
	if err != nil {
		return nil, err
	}

	return controlsConfigEntries(ctx, configGetter, policyGetter, tenant.GetContextName())
}

// controlsConfigEntries pairs the resolved configuration with the controls that
// read it. Both lookups are required: without the values there is nothing to
// report, and without the policies every entry would be an orphan.
func controlsConfigEntries(ctx context.Context, configGetter getter.IControlsInputsGetter, policyGetter getter.IPolicyGetter, clusterName string) ([]metav1.ControlConfigEntry, error) {
	values, err := configGetter.GetControlsInputs(ctx, clusterName)
	if err != nil {
		return nil, err
	}

	frameworks, err := policyGetter.GetFrameworks()
	if err != nil {
		return nil, err
	}

	return buildControlsConfigEntries(values, frameworks), nil
}

// buildControlsConfigEntries indexes every configurable input declared by a
// control against the resolved values. Inputs a control declares but the
// configuration does not set are still listed, with no values, since an unset
// input is what makes a configurable control fall back to its rule default.
func buildControlsConfigEntries(values map[string][]string, frameworks []reporthandling.Framework) []metav1.ControlConfigEntry {
	titles := map[string]string{}
	descriptions := map[string]string{}
	controls := map[string]map[string]struct{}{}

	for i := range frameworks {
		for j := range frameworks[i].Controls {
			control := &frameworks[i].Controls[j]
			for k := range control.Rules {
				for _, input := range control.Rules[k].ControlConfigInputs {
					key := configInputKey(input)
					if key == "" {
						continue
					}
					if _, ok := controls[key]; !ok {
						controls[key] = map[string]struct{}{}
					}
					controls[key][control.ControlID] = struct{}{}
					if titles[key] == "" {
						titles[key] = input.Name
					}
					if descriptions[key] == "" {
						descriptions[key] = input.Description
					}
				}
			}
		}
	}

	names := make([]string, 0, len(values)+len(controls))
	seen := map[string]struct{}{}
	for name := range values {
		names = append(names, name)
		seen[name] = struct{}{}
	}
	for name := range controls {
		if _, ok := seen[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	entries := make([]metav1.ControlConfigEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, metav1.ControlConfigEntry{
			Name:        name,
			Title:       titles[name],
			Description: descriptions[name],
			Values:      append([]string{}, values[name]...),
			Controls:    sortedKeys(controls[name]),
		})
	}
	return entries
}

// configInputKey returns the controls-config key a declared input reads. The
// controls address it by a dotted path such as
// settings.postureControlInputs.imageRepositoryAllowList, while a
// controls-config file is keyed by the last segment alone.
func configInputKey(input reporthandling.ControlConfigInputs) string {
	if input.Path != "" {
		if idx := strings.LastIndex(input.Path, "."); idx != -1 {
			return input.Path[idx+1:]
		}
		return input.Path
	}
	return input.Name
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func jsonControlsConfigFormat(entries []metav1.ControlConfigEntry) {
	j, _ := json.MarshalIndent(entries, "", "  ")

	fmt.Printf("%s\n", j)
}

func yamlControlsConfigFormat(entries []metav1.ControlConfigEntry) {
	y, err := yaml.Marshal(entries)
	if err != nil {
		return
	}

	fmt.Printf("%s\n", y)
}

func csvControlsConfigFormat(entries []metav1.ControlConfigEntry) {
	writer := csv.NewWriter(os.Stdout)
	_ = writer.Write([]string{"name", "title", "values", "controls", "description"})
	for _, entry := range entries {
		_ = writer.Write([]string{
			entry.Name,
			entry.Title,
			strings.Join(entry.Values, ";"),
			strings.Join(entry.Controls, ";"),
			entry.Description,
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write csv output: %v\n", err)
	}
}

func prettyPrintControlsConfig(ctx context.Context, entries []metav1.ControlConfigEntry) {
	configTable := table.NewWriter()
	configTable.SetOutputMirror(printer.GetWriter(ctx, ""))

	configTable.Style().Options.SeparateHeader = true
	configTable.Style().Options.SeparateRows = true
	configTable.Style().Format.HeaderAlign = text.AlignLeft
	configTable.Style().Format.Header = text.FormatDefault
	configTable.Style().Box = table.StyleBoxRounded

	rows := make([]table.Row, 0, len(entries))
	for _, entry := range entries {
		values := strings.Join(entry.Values, "\n")
		if values == "" {
			values = "<unset>"
		}
		rows = append(rows, table.Row{entry.Name, entry.Title, values, strings.Join(entry.Controls, "\n")})
	}

	configTable.AppendHeader(table.Row{"Key", "Configuration", "Value", "Controls"})
	configTable.AppendRows(rows)
	configTable.Render()
}

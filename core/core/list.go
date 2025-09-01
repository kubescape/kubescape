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

var listFunc = map[string]func(context.Context, *metav1.ListPolicies) ([]string, error){
	"controls":   listControls,
	"frameworks": listFrameworks,
	"exceptions": listExceptions,
}

var listFormatFunc = map[string]func(context.Context, string, []string){
	"pretty-print": prettyPrintListFormat,
	"json":         jsonListFormat,
}

func ListSupportActions() []string {
	commands := []string{}
	for key := range listFunc {
		commands = append(commands, key)
	}

	// Sort the keys
	sort.Strings(commands)
	return commands
}
func (ks *Kubescape) List(listPolicies *metav1.ListPolicies) error {
	if policyListerFunc, ok := listFunc[listPolicies.Target]; ok {
		policies, err := policyListerFunc(ks.Context(), listPolicies)
		if err != nil {
			return err
		}
		policies = naturalSortPolicies(policies)

		if listFormatFunction, ok := listFormatFunc[listPolicies.Format]; ok {
			listFormatFunction(ks.Context(), listPolicies.Target, policies)
		} else {
			return fmt.Errorf("Invalid format \"%s\", Supported formats: 'pretty-print'/'json' ", listPolicies.Format)
		}

		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func naturalSortPolicies(policies []string) []string {
	sort.Slice(policies, func(i, j int) bool {
		return natural.Less(policies[i], policies[j])
	})
	return policies
}

func listFrameworks(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface
	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), true, nil)

	return listFrameworksNames(policyGetter), nil
}

func listControls(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, listPolicies.AccessKey, "", "", getKubernetesApi()) // change k8sinterface

	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, nil)
	return policyGetter.ListControls()
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
	if targetPolicy == "controls" {
		prettyPrintControls(ctx, policies)
		return
	}

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

func prettyPrintControls(ctx context.Context, policies []string) {
	controlsTable := table.NewWriter()
	controlsTable.SetOutputMirror(printer.GetWriter(ctx, ""))

	controlsTable.Style().Options.SeparateHeader = true
	controlsTable.Style().Options.SeparateRows = true
	controlsTable.Style().Format.HeaderAlign = text.AlignLeft
	controlsTable.Style().Format.Header = text.FormatDefault
	controlsTable.Style().Box = table.StyleBoxRounded
	controlsTable.SetColumnConfigs([]table.ColumnConfig{{Number: 1, Align: text.AlignRight}})

	controlRows := generateControlRows(policies)

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

func generateControlRows(policies []string) []table.Row {
	rows := make([]table.Row, 0, len(policies))

	for _, control := range policies {

		idAndControlAndFrameworks := strings.Split(control, "|")

		var id, control, framework string

		switch len(idAndControlAndFrameworks) {
		case 0:
			continue
		case 1:
			id = idAndControlAndFrameworks[0]
		case 2:
			id, control = idAndControlAndFrameworks[0], idAndControlAndFrameworks[1]
		default:
			id, control, framework = idAndControlAndFrameworks[0], idAndControlAndFrameworks[1], idAndControlAndFrameworks[2]
		}

		docs := cautils.GetControlLink(id)

		currentRow := table.Row{id, control, docs, strings.Replace(framework, " ", "\n", -1)}

		rows = append(rows, currentRow)
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
		rows = append(rows, table.Row{fmt.Sprintf("Control ID"+strings.Repeat(" ", 3)+": %+v\nControl Name"+strings.Repeat(" ", 1)+": %+v\nDocs"+strings.Repeat(" ", 9)+": %+v\nFrameworks"+strings.Repeat(" ", 3)+": %+v", controlRow[0], controlRow[1], controlRow[2], strings.Replace(controlRow[3].(string), "\n", " ", -1))})
	}
	return rows
}

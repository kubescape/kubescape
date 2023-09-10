package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	v2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/olekukonko/tablewriter"
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
	for k := range listFunc {
		commands = append(commands, k)
	}
	return commands
}
func (ks *Kubescape) List(ctx context.Context, listPolicies *metav1.ListPolicies) error {
	if policyListerFunc, ok := listFunc[listPolicies.Target]; ok {
		policies, err := policyListerFunc(ctx, listPolicies)
		if err != nil {
			return err
		}
		sort.Strings(policies)

		if listFormatFunction, ok := listFormatFunc[listPolicies.Format]; ok {
			listFormatFunction(ctx, listPolicies.Target, policies)
		} else {
			return fmt.Errorf("Invalid format \"%s\", Supported formats: 'pretty-print'/'json' ", listPolicies.Format)
		}

		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func listFrameworks(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, "", "", getKubernetesApi()) // change k8sinterface
	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), true, nil)

	return listFrameworksNames(policyGetter), nil
}

func listControls(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, "", "", getKubernetesApi()) // change k8sinterface

	policyGetter := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, nil)
	return policyGetter.ListControls()
}

func listExceptions(ctx context.Context, listPolicies *metav1.ListPolicies) ([]string, error) {
	// load tenant metav1
	tenant := cautils.GetTenantConfig(listPolicies.AccountID, "", "", getKubernetesApi())

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

	policyTable := tablewriter.NewWriter(printer.GetWriter(ctx, ""))

	policyTable.SetAutoWrapText(true)
	header := fmt.Sprintf("Supported %s", targetPolicy)
	policyTable.SetHeader([]string{header})
	policyTable.SetHeaderLine(true)
	policyTable.SetRowLine(true)
	policyTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	policyTable.SetAutoFormatHeaders(false)
	policyTable.SetAlignment(tablewriter.ALIGN_CENTER)
	policyTable.SetUnicodeHV(tablewriter.Regular, tablewriter.Regular)
	data := v2.Matrix{}

	controlRows := generatePolicyRows(policies)

	var headerColors []tablewriter.Colors
	for range controlRows[0] {
		headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
	}
	policyTable.SetHeaderColor(headerColors...)

	data = append(data, controlRows...)

	policyTable.AppendBulk(data)
	policyTable.Render()
}

func jsonListFormat(_ context.Context, _ string, policies []string) {
	j, _ := json.MarshalIndent(policies, "", "  ")

	fmt.Printf("%s\n", j)
}

func prettyPrintControls(ctx context.Context, policies []string) {
	controlsTable := tablewriter.NewWriter(printer.GetWriter(ctx, ""))

	controlsTable.SetAutoWrapText(false)
	controlsTable.SetHeaderLine(true)
	controlsTable.SetRowLine(true)
	controlsTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	controlsTable.SetAutoFormatHeaders(false)
	controlsTable.SetUnicodeHV(tablewriter.Regular, tablewriter.Regular)

	controlRows := generateControlRows(policies)

	short := utils.CheckShortTerminalWidth(controlRows, []string{"Control ID", "Control Name", "Docs", "Frameworks"})
	if short {
		controlsTable.SetAutoWrapText(false)
		controlsTable.SetHeader([]string{"Controls"})
		controlRows = shortFormatControlRows(controlRows)
	} else {
		controlsTable.SetHeader([]string{"Control ID", "Control Name", "Docs", "Frameworks"})
	}
	var headerColors []tablewriter.Colors
	for range controlRows[0] {
		headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
	}
	controlsTable.SetHeaderColor(headerColors...)

	data := v2.Matrix{}
	data = append(data, controlRows...)

	controlsTable.AppendBulk(data)
	controlsTable.Render()
}

func generateControlRows(policies []string) [][]string {
	rows := [][]string{}

	for _, control := range policies {
		idAndControlAndFrameworks := strings.Split(control, "|")
		id, control, framework := idAndControlAndFrameworks[0], idAndControlAndFrameworks[1], idAndControlAndFrameworks[2]

		docs := cautils.GetControlLink(id)

		currentRow := []string{id, control, docs, strings.Replace(framework, " ", "\n", -1)}

		rows = append(rows, currentRow)
	}

	return rows
}

func generatePolicyRows(policies []string) [][]string {
	rows := [][]string{}

	for _, policy := range policies {
		currentRow := []string{policy}
		rows = append(rows, currentRow)
	}
	return rows
}

func shortFormatControlRows(controlRows [][]string) [][]string {
	rows := [][]string{}
	for _, controlRow := range controlRows {
		rows = append(rows, []string{fmt.Sprintf("Control ID"+strings.Repeat(" ", 3)+": %+v\nControl Name"+strings.Repeat(" ", 1)+": %+v\nDocs"+strings.Repeat(" ", 9)+": %+v\nFrameworks"+strings.Repeat(" ", 3)+": %+v", controlRow[0], controlRow[1], controlRow[2], strings.Replace(controlRow[3], "\n", " ", -1))})
	}
	return rows
}

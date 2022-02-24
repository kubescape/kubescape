package v2

import (
	"fmt"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/olekukonko/tablewriter"
)

func (prettyPrinter *PrettyPrinter) resourceTable(results map[string]resourcesresults.Result, allResources map[string]workloadinterface.IMetadata) {
	if prettyPrinter.outputVersion != "v2" {
		return
	}
	summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
	summaryTable.SetAutoWrapText(true)
	summaryTable.SetAutoMergeCells(true)
	summaryTable.SetHeader(generateResourceHeader())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetRowLine(true)
	// summaryTable.SetFooter([]string{"", "", "Total", "", "$146.93"})
	// For control scan framework will be nil
	data := [][]string{}
	for i := range results {
		resource, ok := allResources[i]
		if !ok {
			continue
		}
		s := results[i]
		if raw := generateResourceRows(resource, s.ListControls(), prettyPrinter.verboseMode); len(raw) > 0 {
			data = append(data, raw...)
		}
	}
	sortTable(data)
	summaryTable.AppendBulk(data)

	summaryTable.Render()
}

func generateResourceRows(resource workloadinterface.IMetadata, controls []resourcesresults.ResourceAssociatedControl, verboseMode bool) [][]string {
	rows := [][]string{}

	for i := range controls {

		if controls[i].GetName() == "" {
			continue
		}
		row := []string{}

		if !verboseMode && controls[i].GetStatus(nil).IsPassed() {
			continue
		}

		row = append(row, fmt.Sprintf("%s\nhttps://hub.armo.cloud/docs/%s", controls[i].GetName(), strings.ToLower(controls[i].GetID())))
		row = append(row, resource.GetNamespace())
		var paths []string
		for j := range controls[i].ResourceAssociatedRules {
			for k := range controls[i].ResourceAssociatedRules[j].Paths {
				if p := controls[i].ResourceAssociatedRules[j].Paths[k].FailedPath; p != "" {
					paths = append(paths, p)
				}
				if p := controls[i].ResourceAssociatedRules[j].Paths[k].FixPath.Path; p != "" {
					v := controls[i].ResourceAssociatedRules[j].Paths[k].FixPath.Value
					paths = append(paths, fmt.Sprintf("%s=%s", p, v))
				}
			}
		}
		row = append(row, fmt.Sprintf("%s/%s\n%s", resource.GetKind(), resource.GetName(), strings.Join(paths, ";\n")))
		row = append(row, string(controls[i].GetStatus(nil).Status()))
		rows = append(rows, row)
	}

	return rows
}

func generateResourceHeader() []string {
	return []string{"Control", "Namespace", "Kind/Name", "Statues"}
}

func sortTable(data [][]string) {

	for j := len(data[0]) - 1; j >= 0; j-- {
		for k := 0; k < len(data)-2; {
			if data[k][j] > data[k+1][j] {
				tmp := data[k]
				data[k] = data[k+1]
				data[k+1] = tmp
				k = 0
			} else {
				k++
			}
		}
	}
}

package configurationprinter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// bucketControlsByCategory groups every control by the category it carries in
// its own metadata (sub-category preferred when present). Unlike the previous
// hardcoded-ID approach this never silently drops controls added to the rego
// library after the printer was last updated.
func bucketControlsByCategory(controlSummaries []reportsummary.IControlSummary) map[string]CategoryControls {
	mapCategoriesToCtrlSummary := map[string][]reportsummary.IControlSummary{}
	mapCategoryIDToName := make(map[string]string)

	for i := range controlSummaries {
		cat := controlSummaries[i].GetCategory()
		if cat == nil {
			continue
		}
		catID, catName := cat.ID, cat.Name
		if cat.SubCategory != nil && cat.SubCategory.ID != "" {
			catID, catName = cat.SubCategory.ID, cat.SubCategory.Name
		}
		if _, ok := mapCategoriesToCtrlSummary[catID]; !ok {
			mapCategoryIDToName[catID] = catName
			mapCategoriesToCtrlSummary[catID] = []reportsummary.IControlSummary{}
		}
		mapCategoriesToCtrlSummary[catID] = append(mapCategoriesToCtrlSummary[catID], controlSummaries[i])
	}

	return buildCategoryToControlsMap(mapCategoriesToCtrlSummary, mapCategoryIDToName)
}

// categoryRenderOrder returns preferredOrder entries that are present in
// categoriesToControls (in that order), then any other category IDs found in
// categoriesToControls appended alphabetically. This guarantees no bucket is
// silently skipped while preserving the curated ordering for known categories.
func categoryRenderOrder(preferredOrder []string, categoriesToControls map[string]CategoryControls) []string {
	out := make([]string, 0, len(categoriesToControls))
	seen := make(map[string]bool, len(preferredOrder))
	for _, id := range preferredOrder {
		if _, ok := categoriesToControls[id]; ok {
			out = append(out, id)
			seen[id] = true
		}
	}
	extras := make([]string, 0)
	for id := range categoriesToControls {
		if !seen[id] {
			extras = append(extras, id)
		}
	}
	sort.Strings(extras)
	return append(out, extras...)
}

// returns map of category ID to category controls (name and controls)
// controls will be on the map only if the are in the mapClusterControlsToCategories map
func mapCategoryToSummary(controlSummaries []reportsummary.IControlSummary, mapDisplayCtrlIDToCategory map[string]string) map[string]CategoryControls {

	mapCategoriesToCtrlSummary := map[string][]reportsummary.IControlSummary{}
	// helper map to get the category name
	mapCategoryIDToName := make(map[string]string)

	for i := range controlSummaries {
		// check if we need to print this control
		category, ok := mapDisplayCtrlIDToCategory[controlSummaries[i].GetID()]
		if !ok {
			continue
		}

		if controlSummaries[i].GetCategory() == nil {
			continue
		}

		// the category on the map can be either category or subcategory, so we need to check both
		if controlSummaries[i].GetCategory().ID == category {
			if _, ok := mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().ID]; !ok {
				mapCategoryIDToName[controlSummaries[i].GetCategory().ID] = controlSummaries[i].GetCategory().Name // set category name
				mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().ID] = []reportsummary.IControlSummary{}

			}
			mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().ID] = append(mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().ID], controlSummaries[i])
			continue
		}

		if controlSummaries[i].GetCategory().SubCategory == nil {
			continue
		}

		if controlSummaries[i].GetCategory().SubCategory.ID == category {
			if _, ok := mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().SubCategory.ID]; !ok {
				mapCategoryIDToName[controlSummaries[i].GetCategory().SubCategory.ID] = controlSummaries[i].GetCategory().SubCategory.Name // set category name
				mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().SubCategory.ID] = []reportsummary.IControlSummary{}
			}
			mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().SubCategory.ID] = append(mapCategoriesToCtrlSummary[controlSummaries[i].GetCategory().SubCategory.ID], controlSummaries[i])
			continue
		}
	}

	mapCategoryToControls := buildCategoryToControlsMap(mapCategoriesToCtrlSummary, mapCategoryIDToName)

	return mapCategoryToControls
}

// returns map of category ID to category controls (name and controls)
func buildCategoryToControlsMap(mapCategoriesToCtrlSummary map[string][]reportsummary.IControlSummary, mapCategoryIDToName map[string]string) map[string]CategoryControls {
	mapCategoryToControls := make(map[string]CategoryControls)
	for categoryID, ctrls := range mapCategoriesToCtrlSummary {
		status := apis.StatusPassed
		for _, ctrl := range ctrls {
			if ctrl.GetStatus().Status() == apis.StatusFailed {
				status = apis.StatusFailed
				break
			}
		}

		categoryName := mapCategoryIDToName[categoryID]
		mapCategoryToControls[categoryID] = CategoryControls{
			CategoryName:     categoryName,
			controlSummaries: ctrls,
			Status:           status,
		}
	}
	return mapCategoryToControls
}

// returns doc link for control
func getDocsForControl(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("%s/%s", docsPrefix, strings.ToLower(controlSummary.GetID()))
}

// returns run command with verbose for control
func getRunCommandForControl(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("%s %s -v", scanControlPrefix, controlSummary.GetID())
}

func sortControlSummaries(controlSummaries []reportsummary.IControlSummary) {
	sort.Slice(controlSummaries, func(i, j int) bool {
		return controlSummaries[i].GetName() < controlSummaries[j].GetName()
	})
}

func printCategoryInfo(writer io.Writer, infoToPrintInfo []utils.InfoStars) {
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(writer, fmt.Sprintf("%s %s\n", infoToPrintInfo[i].Stars, infoToPrintInfo[i].Info))
	}
}

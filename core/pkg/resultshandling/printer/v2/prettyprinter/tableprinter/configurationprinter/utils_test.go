package configurationprinter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func TestMapCategoryToSummary(t *testing.T) {

	tests := []struct {
		name                       string
		ctrlSummaries              map[string]reportsummary.ControlSummary
		mapDisplayCtrlIDToCategory map[string]string
		expected                   map[string]CategoryControls
	}{
		{
			name: "controls mapped to right categories",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName2": {
					ControlID: "ctrlID2",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName3": {
					ControlID: "ctrlID3",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category2",
						ID:   "catID2",
					},
				},
			},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID1": "catID1",
				"ctrlID2": "catID1",
				"ctrlID3": "catID2",
			},
			expected: map[string]CategoryControls{
				"catID1": {
					CategoryName: "category1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID1",
						},
						&reportsummary.ControlSummary{
							ControlID: "ctrlID2",
						},
					},
				},
				"catID2": {
					CategoryName: "category2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
					},
				},
			},
		},
		{
			name: "empty display map",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName2": {
					ControlID: "ctrlID2",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName3": {
					ControlID: "ctrlID3",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category2",
						ID:   "catID2",
					},
				},
			},
			mapDisplayCtrlIDToCategory: map[string]string{},
			expected:                   map[string]CategoryControls{},
		},
		{
			name: "controls not in map are not mapped",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName2": {
					ControlID: "ctrlID2",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				},
				"controlName3": {
					ControlID: "ctrlID3",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category2",
						ID:   "catID2",
					},
				},
			},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID3": "catID2",
			},
			expected: map[string]CategoryControls{
				"catID2": {
					CategoryName: "category2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
					},
				},
			},
		},
		{
			name: "controls mapped to right sub-categories",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory1",
							ID:   "subCatID1",
						},
					},
				},
				"controlName2": {
					ControlID: "ctrlID2",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory1",
							ID:   "subCatID1",
						},
					},
				},
				"controlName3": {
					ControlID: "ctrlID3",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category2",
						ID:   "catID2",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory2",
							ID:   "subCatID2",
						},
					},
				},
			},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID1": "subCatID1",
				"ctrlID2": "subCatID1",
				"ctrlID3": "subCatID2",
			},
			expected: map[string]CategoryControls{
				"subCatID1": {
					CategoryName: "subCategory1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID1",
						},
						&reportsummary.ControlSummary{
							ControlID: "ctrlID2",
						},
					},
				},
				"subCatID2": {
					CategoryName: "subCategory2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
					},
				},
			},
		},
		{
			name: "controls mapped to categories and sub-categories",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory1",
							ID:   "subCatID1",
						},
					},
				},
				"controlName2": {
					ControlID: "ctrlID2",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory1",
							ID:   "subCatID1",
						},
					},
				},
				"controlName3": {
					ControlID: "ctrlID3",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category2",
						ID:   "catID2",
						SubCategory: &reporthandling.SubCategory{
							Name: "subCategory2",
							ID:   "subCatID2",
						},
					},
				},
			},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID1": "catID1",
				"ctrlID2": "subCatID1",
				"ctrlID3": "subCatID2",
			},
			expected: map[string]CategoryControls{
				"catID1": {
					CategoryName: "category1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID1",
						},
					},
				},
				"subCatID1": {
					CategoryName: "subCategory1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID2",
						},
					},
				},
				"subCatID2": {
					CategoryName: "subCategory2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
					},
				},
			},
		},
		{
			name: "nil category",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
				}},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID1": "catID1",
			},
			expected: map[string]CategoryControls{},
		},
		{
			name: "nil sub category",
			ctrlSummaries: map[string]reportsummary.ControlSummary{
				"controlName1": {
					ControlID: "ctrlID1",
					Status:    apis.StatusFailed,
					Category: &reporthandling.Category{
						Name: "category1",
						ID:   "catID1",
					},
				}},
			mapDisplayCtrlIDToCategory: map[string]string{
				"ctrlID1": "subCatID1",
			},
			expected: map[string]CategoryControls{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summaryDetails := reportsummary.SummaryDetails{
				Controls: test.ctrlSummaries,
			}

			actual := mapCategoryToSummary(summaryDetails.ListControls(), test.mapDisplayCtrlIDToCategory)

			if len(actual) != len(test.expected) {
				t.Errorf("expected %d categories, got %d", len(test.expected), len(actual))
			}

			for categoryID, category := range actual {
				expectedCategory, ok := test.expected[categoryID]
				if !ok {
					t.Errorf("unexpected category %s", categoryID)
				}

				if category.CategoryName != expectedCategory.CategoryName {
					t.Errorf("expected category name %s, got %s", test.expected[category.CategoryName].CategoryName, category.CategoryName)
				}

				if len(category.controlSummaries) != len(expectedCategory.controlSummaries) {
					t.Errorf("expected %d controls, got %d", len(test.expected[category.CategoryName].controlSummaries), len(category.controlSummaries))
				}

				for i := range category.controlSummaries {
					found := false
					for j := range expectedCategory.controlSummaries {
						if category.controlSummaries[i].GetID() == expectedCategory.controlSummaries[j].GetID() {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("unexpected control %s", category.controlSummaries[i].GetID())
					}
				}

			}
		})
	}
}

func TestBuildCategoryToControlsMap(t *testing.T) {
	tests := []struct {
		name                       string
		mapCategoriesToCtrlSummary map[string][]reportsummary.ControlSummary
		mapCategoryIDToName        map[string]string
		expected                   map[string]CategoryControls
	}{
		{
			name: "build map of categories to controls",
			mapCategoriesToCtrlSummary: map[string][]reportsummary.ControlSummary{
				"catID1": {
					{
						ControlID: "ctrlID1",
					},
				},
				"catID2": {
					{
						ControlID: "ctrlID2",
					},
				},
				"catID3": {
					{
						ControlID: "ctrlID3",
					},
					{
						ControlID: "ctrlID4",
					},
				},
			},
			mapCategoryIDToName: map[string]string{
				"catID1": "category1",
				"catID2": "category2",
				"catID3": "category3",
			},
			expected: map[string]CategoryControls{
				"catID1": {
					CategoryName: "category1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID1",
						},
					},
				},
				"catID2": {
					CategoryName: "category2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID2",
						},
					},
				},
				"catID3": {
					CategoryName: "category3",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
						&reportsummary.ControlSummary{
							ControlID: "ctrlID4",
						},
					},
				},
			},
		},
		{
			name:                       "build map of categories to controls with empty map",
			mapCategoriesToCtrlSummary: map[string][]reportsummary.ControlSummary{},
			mapCategoryIDToName:        map[string]string{},
			expected:                   map[string]CategoryControls{},
		},
		{
			name: "two categories with same name",
			mapCategoriesToCtrlSummary: map[string][]reportsummary.ControlSummary{
				"catID1": {
					{
						ControlID: "ctrlID1",
					},
				},
				"catID2": {
					{
						ControlID: "ctrlID2",
					},
				},
				"catID3": {
					{
						ControlID: "ctrlID3",
					},
				},
			},
			mapCategoryIDToName: map[string]string{
				"catID1": "category1",
				"catID2": "category1",
				"catID3": "category2",
			},
			expected: map[string]CategoryControls{
				"catID1": {
					CategoryName: "category1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID1",
						},
					},
				},
				"catID2": {
					CategoryName: "category1",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID2",
						},
					},
				},
				"catID3": {
					CategoryName: "category2",
					controlSummaries: []reportsummary.IControlSummary{
						&reportsummary.ControlSummary{
							ControlID: "ctrlID3",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ctrlSummaries := make(map[string][]reportsummary.IControlSummary, 0)
			for id, summaries := range test.mapCategoriesToCtrlSummary {
				for _, summary := range summaries {
					if _, ok := ctrlSummaries[id]; !ok {
						ctrlSummaries[id] = []reportsummary.IControlSummary{}
					}
					ctrlSummaries[id] = append(ctrlSummaries[id], &summary)
				}
			}

			actual := buildCategoryToControlsMap(ctrlSummaries, test.mapCategoryIDToName)

			if len(actual) != len(test.expected) {
				t.Errorf("expected %d categories, got %d", len(test.expected), len(actual))
			}

			for categoryID, category := range actual {
				expectedCategory, ok := test.expected[categoryID]
				if !ok {
					t.Errorf("unexpected category %s", categoryID)
				}

				if category.CategoryName != expectedCategory.CategoryName {
					t.Errorf("expected category name %s, got %s", test.expected[category.CategoryName].CategoryName, category.CategoryName)
				}

				if len(category.controlSummaries) != len(expectedCategory.controlSummaries) {
					t.Errorf("expected %d controls, got %d", len(test.expected[category.CategoryName].controlSummaries), len(category.controlSummaries))
				}

				for i := range category.controlSummaries {
					found := false
					for j := range expectedCategory.controlSummaries {
						if category.controlSummaries[i].GetID() == expectedCategory.controlSummaries[j].GetID() {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("unexpected control %s", category.controlSummaries[i].GetID())
					}
				}

			}
		})
	}
}

func TestGetDocsForControl(t *testing.T) {
	tests := []struct {
		name             string
		controlSummary   reportsummary.IControlSummary
		expectedDocsLink string
	}{
		{
			name: "control with uppercase ID",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrlID1",
			},
			expectedDocsLink: "https://hub.armosec.io/docs/ctrlid1",
		},
		{
			name: "control with lowercase ID",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrlid1",
			},
			expectedDocsLink: "https://hub.armosec.io/docs/ctrlid1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := getDocsForControl(test.controlSummary)

			if actual != test.expectedDocsLink {
				t.Errorf("expected %s, got %s", test.expectedDocsLink, actual)
			}
		})
	}
}

func TestGetRunCommandForControl(t *testing.T) {
	tests := []struct {
		name            string
		controlSummary  reportsummary.IControlSummary
		expectedRunLink string
	}{
		{
			name: "control with uppercase ID",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrlID1",
			},
			expectedRunLink: "$ kubescape scan control ctrlID1 -v",
		},
		{
			name: "control with lowercase ID",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrlid1",
			},
			expectedRunLink: "$ kubescape scan control ctrlid1 -v",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualLink := getRunCommandForControl(test.controlSummary)

			if actualLink != test.expectedRunLink {
				t.Errorf("expected %s, got %s", test.expectedRunLink, actualLink)
			}
		})
	}
}

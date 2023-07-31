package cautils

// func TestSetTopWorkloads(t *testing.T) {
// 	tests := []struct {
// 		name                 string
// 		resourcesPrioritized map[string]prioritization.PrioritizedResource
// 		allResources         map[string]workloadinterface.IMetadata
// 		resourcesSource      map[string]reporthandling.Source
// 		want                 []reportsummary.TopWorkload
// 	}{{
// 		name: "Test 1",
// 		resourcesPrioritized: map[string]prioritization.PrioritizedResource{
// 			"1": {
// 				Score: 1,
// 			},
// 		},
// 		allResources: map[string]workloadinterface.IMetadata{
// 			"1": &workloadinterface.BaseObject{},
// 		},
// 	}}

// 	for _, tt := range tests {
// 		opaSessionObj := OPASessionObj{
// 			ResourcesPrioritized: tt.resourcesPrioritized,
// 		}
// 		t.Run(tt.name, func(t *testing.T) {
// 			opaSessionObj.SetTopWorkloads()
// 			if len(opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore) != len(tt.want) {
// 				t.Errorf("got %d, want %d", len(opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore), len(tt.want))
// 			}

// 			for i := 0; i < len(opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore); i++ {
// 				if opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetKind() != tt.want[i].Workload.GetKind() {
// 					t.Errorf("got %s, want %s", opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetKind(), tt.want[i].Workload.GetKind())
// 				}
// 				if opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetName() != tt.want[i].Workload.GetName() {
// 					t.Errorf("got %s, want %s", opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetName(), tt.want[i].Workload.GetName())
// 				}
// 				if opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetNamespace() != tt.want[i].Workload.GetNamespace() {
// 					t.Errorf("got %s, want %s", opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].Workload.GetNamespace(), tt.want[i].Workload.GetNamespace())
// 				}
// 				if opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].ResourceSource != tt.want[i].ResourceSource {
// 					t.Errorf("got %s, want %s", opaSessionObj.Report.SummaryDetails.TopWorkloadsByScore[i].ResourceSource, tt.want[i].ResourceSource)
// 				}
// 			}
// 		})
// 	}
// }

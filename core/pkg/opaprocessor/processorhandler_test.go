package opaprocessor

import (
	"archive/zip"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

var (
	//go:embed testdata/opaSessionObjMock.json
	opaSessionObjMockData string
	//go:embed testdata/opaSessionObjMock1.json
	opaSessionObjMockData1 string
	//go:embed testdata/opaSessionObjMock2.json
	opaSessionObjMockData2 string
	//go:embed testdata/regoDependenciesDataMock.json
	regoDependenciesData string

	allResourcesMockData []byte
	//go:embed testdata/resourcesMock1.json
	resourcesMock1 []byte
	//go:embed testdata/resourcesMock2.json
	resourcesMock2 []byte
)

func unzipAllResourcesTestDataAndSetVar(zipFilePath, destFilePath string) error {
	archive, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return err
	}

	os.RemoveAll(destFilePath)

	f := archive.File[0]
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(destFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}

	fileInArchive, err := f.Open()
	if err != nil {
		return err
	}

	_, err = io.Copy(dstFile, fileInArchive) //nolint:gosec

	dstFile.Close()
	fileInArchive.Close()
	archive.Close()

	file, err := os.Open(destFilePath)
	if err != nil {
		panic(err)
	}
	allResourcesMockData, err = io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	file.Close()

	return nil
}

func NewOPAProcessorMock(opaSessionObjMock string, resourcesMock []byte) *OPAProcessor {
	opap := &OPAProcessor{}
	if err := json.Unmarshal([]byte(regoDependenciesData), &opap.regoDependenciesData); err != nil {
		panic(err)
	}
	// no err check because Unmarshal will fail on AllResources field (expected)
	json.Unmarshal([]byte(opaSessionObjMock), &opap.OPASessionObj)
	opap.AllResources = make(map[string]workloadinterface.IMetadata)

	allResources := make(map[string]map[string]interface{})
	if err := json.Unmarshal(resourcesMock, &allResources); err != nil {
		panic(err)
	}
	for i := range allResources {
		opap.AllResources[i] = workloadinterface.NewWorkloadObj(allResources[i])
	}

	return opap
}

func monitorHeapSpace(maxHeap *uint64, quitChan chan bool) {
	for {
		select {
		case <-quitChan:
			return
		default:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			heapSpace := m.HeapAlloc
			if heapSpace > *maxHeap {
				*maxHeap = heapSpace
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

/*
goarch: arm64
pkg: github.com/kubescape/kubescape/v3/core/pkg/opaprocessor

BenchmarkProcess/opaprocessor.Process_1-8         	       1	29714096083 ns/op	22309913416 B/op	498183685 allocs/op
--- BENCH: BenchmarkProcess/opaprocessor.Process_1-8

	processorhandler_test.go:178: opaprocessor.Process_1_max_heap_space_gb:  2.85
	processorhandler_test.go:179: opaprocessor.Process_1_execution_time_sec: 29.714054

BenchmarkProcess/opaprocessor.Process_4-8         	       1	25574892875 ns/op	22037035032 B/op	498167263 allocs/op
--- BENCH: BenchmarkProcess/opaprocessor.Process_4-8

	processorhandler_test.go:178: opaprocessor.Process_4_max_heap_space_gb:  6.76
	processorhandler_test.go:179: opaprocessor.Process_4_execution_time_sec: 25.574884

BenchmarkProcess/opaprocessor.Process_8-8         	       1	16534461291 ns/op	22308814384 B/op	498167171 allocs/op
--- BENCH: BenchmarkProcess/opaprocessor.Process_8-8

	processorhandler_test.go:178: opaprocessor.Process_8_max_heap_space_gb:  9.47
	processorhandler_test.go:179: opaprocessor.Process_8_execution_time_sec: 16.534455

BenchmarkProcess/opaprocessor.Process_16-8        	       1	18924050500 ns/op	22179562272 B/op	498167367 allocs/op
--- BENCH: BenchmarkProcess/opaprocessor.Process_16-8

		processorhandler_test.go:178: opaprocessor.Process_16_max_heap_space_gb: 11.69
	    processorhandler_test.go:179: opaprocessor.Process_16_execution_time_sec: 16.321493
*/
func BenchmarkProcess(b *testing.B) {
	b.SetParallelism(1)

	// since all resources JSON is a large file, we need to unzip it and set the variable before running the benchmark
	unzipAllResourcesTestDataAndSetVar("testdata/allResourcesMock.json.zip", "testdata/allResourcesMock.json")

	maxGoRoutinesArr := []int{1, 4, 8, 16}
	for _, maxGoRoutines := range maxGoRoutinesArr {
		testName := fmt.Sprintf("opaprocessor.Process_%d", maxGoRoutines)
		b.Run(testName, func(b *testing.B) {
			// setup
			opap := NewOPAProcessorMock(opaSessionObjMockData, allResourcesMockData)
			b.ResetTimer()
			var maxHeap uint64
			quitChan := make(chan bool)
			go monitorHeapSpace(&maxHeap, quitChan)

			// test
			opap.Process(context.Background(), opap.OPASessionObj.AllPolicies, nil)

			// teardown
			quitChan <- true
			b.Log(fmt.Sprintf("%s_max_heap_space_gb:  %.2f", testName, float64(maxHeap)/(1024*1024*1024)))
			b.Log(fmt.Sprintf("%s_execution_time_sec: %f", testName, b.Elapsed().Seconds()))
		})
	}
}

func TestProcessResourcesResult(t *testing.T) {

	// set k8s
	k8sResources := make(cautils.K8SResources)

	deployment := mocks.MockDevelopmentWithHostpath()
	frameworks := []reporthandling.Framework{*mocks.MockFramework_0006_0013()}

	k8sResources["apps/v1/deployments"] = workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{deployment})

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Policies = frameworks

	scanningScope := reporthandling.ScopeCluster
	policies := convertFrameworksToPolicies(opaSessionObj.Policies, nil, scanningScope)
	ConvertFrameworksToSummaryDetails(&opaSessionObj.Report.SummaryDetails, opaSessionObj.Policies, policies)

	opaSessionObj.K8SResources = k8sResources
	opaSessionObj.AllResources[deployment.GetID()] = deployment

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock(), "test")
	opap.AllPolicies = policies
	opap.Process(context.TODO(), policies, nil)

	assert.Equal(t, 1, len(opaSessionObj.ResourcesResult))
	res := opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).Len())
	assert.Equal(t, 1, res.ListControlsIDs(nil).Failed())
	assert.Equal(t, 1, res.ListControlsIDs(nil).Passed())
	assert.True(t, res.GetStatus(nil).IsFailed())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	opap.updateResults(context.TODO())
	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).Len())
	assert.Equal(t, 1, res.ListControlsIDs(nil).Failed())
	assert.Equal(t, 1, res.ListControlsIDs(nil).Passed())
	assert.True(t, res.GetStatus(nil).IsFailed())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	// test resource counters
	summaryDetails := opaSessionObj.Report.SummaryDetails
	assert.Equal(t, 1, summaryDetails.NumberOfResources().All())
	assert.Equal(t, 1, summaryDetails.NumberOfResources().Failed())
	assert.Equal(t, 0, summaryDetails.NumberOfResources().Passed())
	assert.Equal(t, 0, summaryDetails.NumberOfResources().Skipped())

	// test resource listing
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs(nil).Len())
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs(nil).Failed())
	assert.Equal(t, 0, summaryDetails.ListResourcesIDs(nil).Passed())
	assert.Equal(t, 0, summaryDetails.ListResourcesIDs(nil).Skipped())

	// test control listing
	assert.Equal(t, res.ListControlsIDs(nil).Len(), summaryDetails.NumberOfControls().All())
	assert.Equal(t, res.ListControlsIDs(nil).Passed(), summaryDetails.NumberOfControls().Passed())
	assert.Equal(t, res.ListControlsIDs(nil).Skipped(), summaryDetails.NumberOfControls().Skipped())
	assert.Equal(t, res.ListControlsIDs(nil).Failed(), summaryDetails.NumberOfControls().Failed())
	assert.True(t, summaryDetails.GetStatus().IsFailed())

	opaSessionObj.Exceptions = []armotypes.PostureExceptionPolicy{*mocks.MockExceptionAllKinds(&armotypes.PosturePolicy{FrameworkName: frameworks[0].Name})}
	opap.updateResults(context.TODO())

	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).Len())
	assert.Equal(t, 2, res.ListControlsIDs(nil).Passed())
	assert.True(t, res.GetStatus(nil).IsPassed())
	assert.False(t, res.GetStatus(nil).IsFailed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	// test resource listing
	summaryDetails = opaSessionObj.Report.SummaryDetails
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs(nil).Len())
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs(nil).Failed())
	assert.Equal(t, 0, summaryDetails.ListResourcesIDs(nil).Passed())
	assert.Equal(t, 0, summaryDetails.ListResourcesIDs(nil).Skipped())
}

// don't parallelize this test because it uses a global variable - allResourcesMockData
func TestProcessRule(t *testing.T) {
	testCases := []struct {
		name              string
		rule              reporthandling.PolicyRule
		resourcesMock     []byte
		opaSessionObjMock string
		expectedResult    map[string]*resourcesresults.ResourceAssociatedRule
	}{
		{
			name: "TestRelatedResourcesIDs",
			rule: reporthandling.PolicyRule{
				PortalBase: armotypes.PortalBase{
					Name:       "exposure-to-internet",
					Attributes: map[string]interface{}{},
				},
				Rule: "package armo_builtins\n\n# Checks if NodePort or LoadBalancer is connected to a workload to expose something\ndeny[msga] {\n    service := input[_]\n    service.kind == \"Service\"\n    is_exposed_service(service)\n    \n    wl := input[_]\n    spec_template_spec_patterns := {\"Deployment\", \"ReplicaSet\", \"DaemonSet\", \"StatefulSet\", \"Pod\", \"Job\", \"CronJob\"}\n    spec_template_spec_patterns[wl.kind]\n    wl_connected_to_service(wl, service)\n    failPath := [\"spec.type\"]\n    msga := {\n        \"alertMessage\": sprintf(\"workload '%v' is exposed through service '%v'\", [wl.metadata.name, service.metadata.name]),\n        \"packagename\": \"armo_builtins\",\n        \"alertScore\": 7,\n        \"fixPaths\": [],\n        \"failedPaths\": [],\n        \"alertObject\": {\n            \"k8sApiObjects\": [wl]\n        },\n        \"relatedObjects\": [{\n            \"object\": service,\n            \"failedPaths\": failPath,\n   \"reviewPaths\": failPath,\n      }]\n    }\n}\n\n# Checks if Ingress is connected to a service and a workload to expose something\ndeny[msga] {\n    ingress := input[_]\n    ingress.kind == \"Ingress\"\n    \n    svc := input[_]\n    svc.kind == \"Service\"\n    # avoid duplicate alerts\n    # if service is already exposed through NodePort or LoadBalancer workload will fail on that\n    not is_exposed_service(svc)\n\n    wl := input[_]\n    spec_template_spec_patterns := {\"Deployment\", \"ReplicaSet\", \"DaemonSet\", \"StatefulSet\", \"Pod\", \"Job\", \"CronJob\"}\n    spec_template_spec_patterns[wl.kind]\n    wl_connected_to_service(wl, svc)\n\n    result := svc_connected_to_ingress(svc, ingress)\n    \n    msga := {\n        \"alertMessage\": sprintf(\"workload '%v' is exposed through ingress '%v'\", [wl.metadata.name, ingress.metadata.name]),\n        \"packagename\": \"armo_builtins\",\n        \"failedPaths\": [],\n        \"fixPaths\": [],\n        \"alertScore\": 7,\n        \"alertObject\": {\n            \"k8sApiObjects\": [wl]\n        },\n        \"relatedObjects\": [{\n            \"object\": ingress,\n            \"failedPaths\": result,\n     \"reviewPaths\": result,\n    }]\n    }\n} \n\n# ====================================================================================\n\nis_exposed_service(svc) {\n    svc.spec.type == \"NodePort\"\n}\n\nis_exposed_service(svc) {\n    svc.spec.type == \"LoadBalancer\"\n}\n\nwl_connected_to_service(wl, svc) {\n    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)\n}\n\nwl_connected_to_service(wl, svc) {\n    wl.spec.selector.matchLabels == svc.spec.selector\n}\n\n# check if service is connected to ingress\nsvc_connected_to_ingress(svc, ingress) = result {\n    rule := ingress.spec.rules[i]\n    paths := rule.http.paths[j]\n    svc.metadata.name == paths.backend.service.name\n    result := [sprintf(\"ingress.spec.rules[%d].http.paths[%d].backend.service.name\", [i,j])]\n}\n\n",
				Match: []reporthandling.RuleMatchObjects{
					{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"Pod", "Service"},
					},
					{
						APIGroups:   []string{"apps"},
						APIVersions: []string{"v1"},
						Resources:   []string{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet"},
					},
					{
						APIGroups:   []string{"batch"},
						APIVersions: []string{"*"},
						Resources:   []string{"Job", "CronJob"},
					},
					{
						APIGroups:   []string{"extensions", "networking.k8s.io"},
						APIVersions: []string{"v1beta1", "v1"},
						Resources:   []string{"Ingress"},
					},
				},
				Description:  "fails in case the running workload has binded Service or Ingress that are exposing it on Internet.",
				Remediation:  "",
				RuleQuery:    "armo_builtins",
				RuleLanguage: reporthandling.RegoLanguage,
			},
			resourcesMock:     resourcesMock1,
			opaSessionObjMock: opaSessionObjMockData1,
			expectedResult: map[string]*resourcesresults.ResourceAssociatedRule{
				"/v1/default/Pod/fake-pod-1-22gck": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "failed",
					SubStatus:             "",
					Paths: []armotypes.PosturePaths{
						{ResourceID: "/v1/default/Service/fake-service-1", FailedPath: "spec.type"},
						{ResourceID: "/v1/default/Service/fake-service-1", ReviewPath: "spec.type"},
					},
					Exception: nil,
					RelatedResourcesIDs: []string{
						"/v1/default/Service/fake-service-1",
					},
				},
				"/v1/default/Service/fake-service-1": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "passed",
					SubStatus:             "",
					Paths:                 nil,
					Exception:             nil,
					RelatedResourcesIDs:   nil,
				},
			},
		},
		{
			name: "TestMultipleRelatedResources",
			rule: reporthandling.PolicyRule{
				PortalBase: armotypes.PortalBase{
					Name:       "exposure-to-internet",
					Attributes: map[string]interface{}{},
				},
				Rule: "\npackage armo_builtins\n\n# Checks if NodePort or LoadBalancer is connected to a workload to expose something\ndeny[msga] {\n    service := input[_]\n    service.kind == \"Service\"\n    is_exposed_service(service)\n    \n    wl := input[_]\n    spec_template_spec_patterns := {\"Deployment\", \"ReplicaSet\", \"DaemonSet\", \"StatefulSet\", \"Pod\", \"Job\", \"CronJob\"}\n    spec_template_spec_patterns[wl.kind]\n    wl_connected_to_service(wl, service)\n    failPath := [\"spec.type\"]\n    msga := {\n        \"alertMessage\": sprintf(\"workload '%v' is exposed through service '%v'\", [wl.metadata.name, service.metadata.name]),\n        \"packagename\": \"armo_builtins\",\n        \"alertScore\": 7,\n        \"fixPaths\": [],\n        \"failedPaths\": [],\n        \"alertObject\": {\n            \"k8sApiObjects\": [wl]\n        },\n        \"relatedObjects\": [{\n            \"object\": service,\n\t\t    \"reviewPaths\": failPath,\n            \"failedPaths\": failPath,\n        }]\n    }\n}\n\n# Checks if Ingress is connected to a service and a workload to expose something\ndeny[msga] {\n    ingress := input[_]\n    ingress.kind == \"Ingress\"\n    \n    svc := input[_]\n    svc.kind == \"Service\"\n\n    # Make sure that they belong to the same namespace\n    svc.metadata.namespace == ingress.metadata.namespace\n\n    # avoid duplicate alerts\n    # if service is already exposed through NodePort or LoadBalancer workload will fail on that\n    not is_exposed_service(svc)\n\n    wl := input[_]\n    spec_template_spec_patterns := {\"Deployment\", \"ReplicaSet\", \"DaemonSet\", \"StatefulSet\", \"Pod\", \"Job\", \"CronJob\"}\n    spec_template_spec_patterns[wl.kind]\n    wl_connected_to_service(wl, svc)\n\n    result := svc_connected_to_ingress(svc, ingress)\n    \n    msga := {\n        \"alertMessage\": sprintf(\"workload '%v' is exposed through ingress '%v'\", [wl.metadata.name, ingress.metadata.name]),\n        \"packagename\": \"armo_builtins\",\n        \"failedPaths\": [],\n        \"fixPaths\": [],\n        \"alertScore\": 7,\n        \"alertObject\": {\n            \"k8sApiObjects\": [wl]\n        },\n        \"relatedObjects\": [\n\t\t{\n\t            \"object\": ingress,\n\t\t    \"reviewPaths\": result,\n\t            \"failedPaths\": result,\n\t        },\n\t\t{\n\t            \"object\": svc,\n\t\t}\n        ]\n    }\n} \n\n# ====================================================================================\n\nis_exposed_service(svc) {\n    svc.spec.type == \"NodePort\"\n}\n\nis_exposed_service(svc) {\n    svc.spec.type == \"LoadBalancer\"\n}\n\nwl_connected_to_service(wl, svc) {\n    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)\n}\n\nwl_connected_to_service(wl, svc) {\n    wl.spec.selector.matchLabels == svc.spec.selector\n}\n\n# check if service is connected to ingress\nsvc_connected_to_ingress(svc, ingress) = result {\n    rule := ingress.spec.rules[i]\n    paths := rule.http.paths[j]\n    svc.metadata.name == paths.backend.service.name\n    result := [sprintf(\"spec.rules[%d].http.paths[%d].backend.service.name\", [i,j])]\n}\n\n",
				Match: []reporthandling.RuleMatchObjects{
					{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"Pod", "Service"},
					},
					{
						APIGroups:   []string{"apps"},
						APIVersions: []string{"v1"},
						Resources:   []string{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet"},
					},
					{
						APIGroups:   []string{"batch"},
						APIVersions: []string{"*"},
						Resources:   []string{"Job", "CronJob"},
					},
					{
						APIGroups:   []string{"extensions", "networking.k8s.io"},
						APIVersions: []string{"v1beta1", "v1"},
						Resources:   []string{"Ingress"},
					},
				},
				Description:  "fails in case the running workload has binded Service or Ingress that are exposing it on Internet.",
				Remediation:  "",
				RuleQuery:    "armo_builtins",
				RuleLanguage: reporthandling.RegoLanguage,
			},
			resourcesMock:     resourcesMock2,
			opaSessionObjMock: opaSessionObjMockData2,
			expectedResult: map[string]*resourcesresults.ResourceAssociatedRule{
				"apps/v1/default/Deployment/my-app": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "failed",
					SubStatus:             "",
					Paths: []armotypes.PosturePaths{
						{ResourceID: "networking.k8s.io/v1/default/Ingress/my-ingress1", FailedPath: "spec.rules[0].http.paths[0].backend.service.name"},
						{ResourceID: "networking.k8s.io/v1/default/Ingress/my-ingress1", ReviewPath: "spec.rules[0].http.paths[0].backend.service.name"},
						{ResourceID: "networking.k8s.io/v1/default/Ingress/my-ingress2", FailedPath: "spec.rules[0].http.paths[0].backend.service.name"},
						{ResourceID: "networking.k8s.io/v1/default/Ingress/my-ingress2", ReviewPath: "spec.rules[0].http.paths[0].backend.service.name"},
					},
					Exception: nil,
					RelatedResourcesIDs: []string{
						"networking.k8s.io/v1/default/Ingress/my-ingress1",
						"/v1/default/Service/my-service",
						"networking.k8s.io/v1/default/Ingress/my-ingress2",
					},
				},
				"networking.k8s.io/v1/default/Ingress/my-ingress1": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "passed",
					SubStatus:             "",
					Paths:                 nil,
					Exception:             nil,
					RelatedResourcesIDs:   nil,
				},
				"networking.k8s.io/v1/default/Ingress/my-ingress2": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "passed",
					SubStatus:             "",
					Paths:                 nil,
					Exception:             nil,
					RelatedResourcesIDs:   nil,
				},
				"/v1/default/Service/my-service": {
					Name:                  "exposure-to-internet",
					ControlConfigurations: map[string][]string{},
					Status:                "passed",
					SubStatus:             "",
					Paths:                 nil,
					Exception:             nil,
					RelatedResourcesIDs:   nil,
				},
			},
		},
	}
	for _, tc := range testCases {
		// since all resources JSON is a large file, we need to unzip it and set the variable before running the benchmark
		unzipAllResourcesTestDataAndSetVar("testdata/allResourcesMock.json.zip", "testdata/allResourcesMock.json")
		opap := NewOPAProcessorMock(tc.opaSessionObjMock, tc.resourcesMock)
		resources, err := opap.processRule(context.Background(), &tc.rule, nil)
		assert.NoError(t, err)
		assert.Equal(t, tc.expectedResult, resources, t.Name)
	}
}

func TestAppendPaths(t *testing.T) {
	tests := []struct {
		name                string
		paths               []armotypes.PosturePaths
		assistedRemediation reporthandling.AssistedRemediation
		resourceID          string
		expected            []armotypes.PosturePaths
	}{
		{
			name: "Only FixPaths",
			assistedRemediation: reporthandling.AssistedRemediation{
				FixPaths: []armotypes.FixPath{
					{Path: "path2", Value: "command2"},
					{Path: "path3", Value: "command3"},
				},
			},
			resourceID: "2",
			expected: []armotypes.PosturePaths{
				{ResourceID: "2", FixPath: armotypes.FixPath{Path: "path2", Value: "command2"}},
				{ResourceID: "2", FixPath: armotypes.FixPath{Path: "path3", Value: "command3"}},
			},
		},
		{
			name: "Only FixCommand",
			assistedRemediation: reporthandling.AssistedRemediation{
				FixCommand: "fix command",
			},
			resourceID: "2",
			expected: []armotypes.PosturePaths{
				{ResourceID: "2", FixCommand: "fix command"},
			},
		},
		{
			name: "Only DeletePaths",
			assistedRemediation: reporthandling.AssistedRemediation{
				DeletePaths: []string{"path2", "path3"},
			},
			resourceID: "2",
			expected: []armotypes.PosturePaths{
				{ResourceID: "2", DeletePath: "path2"},
				{ResourceID: "2", DeletePath: "path3"},
			},
		},
		{
			name: "Only ReviewPaths",
			assistedRemediation: reporthandling.AssistedRemediation{
				ReviewPaths: []string{"path2", "path3"},
			},
			resourceID: "2",
			expected: []armotypes.PosturePaths{
				{ResourceID: "2", ReviewPath: "path2"},
				{ResourceID: "2", ReviewPath: "path3"},
			},
		},
		{
			name: "All types of paths",
			assistedRemediation: reporthandling.AssistedRemediation{
				FailedPaths: []string{"path2"},
				DeletePaths: []string{"path4", "path5"},
				ReviewPaths: []string{"path6", "path7"},
				FixPaths: []armotypes.FixPath{
					{Path: "path3", Value: "command3"},
				},
				FixCommand: "fix command",
			},
			resourceID: "2",
			expected: []armotypes.PosturePaths{
				{ResourceID: "2", FailedPath: "path2"},
				{ResourceID: "2", DeletePath: "path4"},
				{ResourceID: "2", DeletePath: "path5"},
				{ResourceID: "2", ReviewPath: "path6"},
				{ResourceID: "2", ReviewPath: "path7"},
				{ResourceID: "2", FixPath: armotypes.FixPath{Path: "path3", Value: "command3"}},
				{ResourceID: "2", FixCommand: "fix command"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendPaths(tt.paths, tt.assistedRemediation, tt.resourceID)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}

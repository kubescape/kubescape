package opaprocessor

import (
	"context"
	"encoding/json"
	"kube-escape/cautils"
	"os"
	"path"
	"strings"
	"testing"

	"kube-escape/cautils/k8sinterface"
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
	restclient "k8s.io/client-go/rest"

	"kube-escape/cautils/opapolicy"
	"kube-escape/cautils/opapolicy/resources"

	"github.com/open-policy-agent/opa/ast"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

func NewOPAProcessorMock() *OPAProcessor {
	c := make(chan *cautils.OPASessionObj)

	deps := resources.NewRegoDependenciesDataMock()
	storage, err := deps.TOStorage()
	if err != nil {
		panic(err)
	}
	return &OPAProcessor{
		processedPolicy:    &c,
		reportResults:      &c,
		regoK8sCredentials: storage,
	}
}
func TestProcessRulesHandler(t *testing.T) {
	// set k8s
	k8sResources := make(cautils.K8SResources)
	k8sResources["/v1/pods"] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items)

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Frameworks = []opapolicy.Framework{*opapolicy.MockFrameworkA()}
	opaSessionObj.K8SResources = &k8sResources
	k8sinterface.K8SConfig = &restclient.Config{}

	// run test
	processor := NewOPAProcessorMock()
	if err := processor.ProcessRulesHandler(opaSessionObj); err != nil {
		t.Errorf("%v", err)
	}
	// bla, _ := json.Marshal(opaSessionObj.PostureReport)
	// t.Errorf("%v", string(bla))
}

func TestRunRegoOnK8s(t *testing.T) {
	// set k8s
	k8sResources := make(cautils.K8SResources)
	// k8sResources["/v1/pods"] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items)
	k8sResources["/v1/pods"] = k8sinterface.V1KubeSystemNamespaceMock().Items

	k8sinterface.K8SConfig = &restclient.Config{}

	// run test
	processor := NewOPAProcessorMock()
	report, err := processor.runRegoOnK8s(opapolicy.MockRuleA(), []map[string]interface{}{k8sResources})
	if err != nil {
		t.Errorf("%v", err)
	}
	if len(report.RuleResponses) == 0 {
		t.Errorf("len(report.RuleResponses) == 0")
	}
}

func TestCompromisedRegistries(t *testing.T) {
	// set k8s
	k8sResources := make(cautils.K8SResources)
	// k8sResources["/v1/pods"] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items)
	k8sResources["/v1/pods"] = k8sinterface.V1AllClusterWithCompromisedRegistriesMock().Items
	wd, _ := os.Getwd()
	baseDirName := "kube-escape"
	idx := strings.Index(wd, baseDirName)
	wd = wd[0:idx]
	resources.RegoDependenciesPath = path.Join(wd, "/kube-escape/vendor/asterix.cyberarmor.io/cyberarmor/capacketsgo/opapolicy/resources/rego/dependencies")
	k8sinterface.K8SConfig = &restclient.Config{}

	opaProcessor := NewOPAProcessorMock()

	// run test
	reportB, errB := opaProcessor.runRegoOnK8s(opapolicy.MockRuleUntrustedRegistries(), []map[string]interface{}{k8sResources})
	if errB != nil {
		t.Errorf("%v", errB)
	}
	if len(reportB.RuleResponses) == 0 {
		t.Errorf("len(report.RuleResponses) == 0")
		return
	}
	// bla, _ := json.Marshal(reportB.RuleResponses[0])
	// t.Errorf("%s", bla)
}

// func TestForLior(t *testing.T) {
// 	// set k8s
// 	k8sResources := make(cautils.K8SResources)
// 	// k8sResources["/v1/pods"] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items)
// 	k8sResources["/v1/pods"] = k8sinterface.V1KubeSystemNamespaceMock().Items
// 	resources.RegoDependenciesPath = "/home/david/go/src/kube-escape/vendor/asterix.cyberarmor.io/cyberarmor/capacketsgo/opapolicy/resources/rego/dependencies"
// 	opaProcessor := NewOPAProcessorMock()

// 	// set opaSessionObj
// 	opaSessionObj := cautils.NewOPASessionObjMock()
// 	opaSessionObj.K8SResources = &k8sResources

// 	opaSessionObj.Frameworks = []opapolicy.Framework{*opapolicy.MockFrameworkA()}
// 	opaSessionObj.Frameworks[0].Controls[0].Rules[0] = *opapolicy.MockRuleB()

// 	// run test
// 	reportB, errB := opaProcessor.runRegoOnK8s(opapolicy.MockRuleB(), opaSessionObj)
// 	if errB != nil {
// 		t.Errorf("%v", errB)
// 		return
// 	}
// 	if len(reportB.RuleResponses) == 0 {
// 		t.Errorf("len(report.RuleResponses) == 0")
// 		return
// 	}
// 	bla, _ := json.Marshal(reportB.RuleResponses[0])
// 	t.Errorf("%s", bla)
// }

func TestNewRego(t *testing.T) {
	// TODO - remove before testing
	return

	// k8sConfig := k8sinterface.GetK8sConfig()

	// t.Errorf(fmt.Sprintf("%v", k8sConfig.String()))
	// t.Errorf(fmt.Sprintf("%v", k8sConfig.AuthProvider.Config))
	// return

	ruleName := "some rule"
	rule := opapolicy.MockTemp()
	allResources := []schema.GroupVersionResource{
		{Group: "api-versions", Version: "", Resource: ""},
	}
	namespace := ""
	k8sinterface.K8SConfig = nil

	// compile modules
	modules, err := getRuleDependencies()
	if err != nil {
		t.Errorf("err: %v", err)
		return
	}
	modules[ruleName] = rule
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		t.Errorf("err: %v", err)
		return
	}
	opaProcessor := NewOPAProcessorMock()
	k8s := k8sinterface.NewKubernetesApi()

	// set dynamic object
	var clientResource dynamic.ResourceInterface
	recourceList := []unstructured.Unstructured{}
	for i := range allResources {
		if namespace != "" {
			clientResource = k8s.DynamicClient.Resource(allResources[i]).Namespace(namespace)
		} else {
			clientResource = k8s.DynamicClient.Resource(allResources[i])
		}
		l, err := clientResource.List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		recourceList = append(recourceList, l.Items...)
	}
	inputObj := k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.FilterOutOwneredResources(recourceList))
	// inputObj := k8sinterface.ConvertUnstructuredSliceToMap(l.Items)
	result, err := opaProcessor.regoEval(inputObj, compiled)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	resb, _ := json.Marshal(result)
	t.Errorf("result: %s", resb)

}

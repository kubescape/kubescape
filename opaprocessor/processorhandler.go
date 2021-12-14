package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/golang/glog"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"

	"github.com/armosec/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	uuid "github.com/satori/go.uuid"
)

const ScoreConfigPath = "/resources/config"

type OPAProcessorHandler struct {
	processedPolicy      *chan *cautils.OPASessionObj
	reportResults        *chan *cautils.OPASessionObj
	regoDependenciesData *resources.RegoDependenciesData
}

type OPAProcessor struct {
	*cautils.OPASessionObj
	regoDependenciesData *resources.RegoDependenciesData
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
	}
	return &OPAProcessor{
		OPASessionObj:        sessionObj,
		regoDependenciesData: regoDependenciesData,
	}
}

func NewOPAProcessorHandler(processedPolicy, reportResults *chan *cautils.OPASessionObj) *OPAProcessorHandler {
	return &OPAProcessorHandler{
		processedPolicy:      processedPolicy,
		reportResults:        reportResults,
		regoDependenciesData: resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), cautils.ClusterName),
	}
}

func (opaHandler *OPAProcessorHandler) ProcessRulesListenner() {

	for {
		opaSessionObj := <-*opaHandler.processedPolicy
		opap := NewOPAProcessor(opaSessionObj, opaHandler.regoDependenciesData)

		// process
		if err := opap.Process(); err != nil {
			// fmt.Println(err)
		}

		// edit results
		opap.updateResults()

		// update score
		// opap.updateScore()

		// report
		*opaHandler.reportResults <- opaSessionObj
	}
}

func (opap *OPAProcessor) Process() error {
	// glog.Infof(fmt.Sprintf("Starting 'Process'. reportID: %s", opap.PostureReport.ReportID))
	cautils.ProgressTextDisplay(fmt.Sprintf("Scanning cluster %s", cautils.ClusterName))
	cautils.StartSpinner()
	frameworkReports := []reporthandling.FrameworkReport{}
	var errs error
	for i := range opap.Frameworks {
		frameworkReport, err := opap.processFramework(&opap.Frameworks[i])
		if err != nil {
			appendError(&errs, err)
		}
		frameworkReports = append(frameworkReports, *frameworkReport)
	}

	opap.PostureReport.FrameworkReports = frameworkReports
	opap.PostureReport.ReportID = uuid.NewV4().String()
	opap.PostureReport.ReportGenerationTime = time.Now().UTC()
	// glog.Infof(fmt.Sprintf("Done 'Process'. reportID: %s", opap.PostureReport.ReportID))
	cautils.StopSpinner()
	cautils.SuccessTextDisplay(fmt.Sprintf("Done scanning cluster %s", cautils.ClusterName))
	return errs
}

func appendError(errs *error, err error) {
	if err == nil {
		return
	}
	if errs == nil {
		errs = &err
	} else {
		*errs = fmt.Errorf("%v\n%s", *errs, err.Error())
	}
}
func (opap *OPAProcessor) processFramework(framework *reporthandling.Framework) (*reporthandling.FrameworkReport, error) {
	var errs error

	frameworkReport := reporthandling.FrameworkReport{}
	frameworkReport.Name = framework.Name

	controlReports := []reporthandling.ControlReport{}
	for i := range framework.Controls {
		controlReport, err := opap.processControl(&framework.Controls[i])
		if err != nil {
			appendError(&errs, err)
			// errs = fmt.Errorf("%v\n%s", errs, err.Error())
		}
		if controlReport != nil {
			controlReports = append(controlReports, *controlReport)
		}
	}
	frameworkReport.ControlReports = controlReports
	return &frameworkReport, errs
}

func (opap *OPAProcessor) processControl(control *reporthandling.Control) (*reporthandling.ControlReport, error) {
	var errs error

	controlReport := reporthandling.ControlReport{}
	controlReport.PortalBase = control.PortalBase
	controlReport.ControlID = control.ControlID
	controlReport.BaseScore = control.BaseScore

	controlReport.Control_ID = control.Control_ID // TODO: delete when 'id' is deprecated

	controlReport.Name = control.Name
	controlReport.Description = control.Description
	controlReport.Remediation = control.Remediation

	ruleReports := []reporthandling.RuleReport{}
	for i := range control.Rules {
		ruleReport, err := opap.processRule(&control.Rules[i])
		if err != nil {
			appendError(&errs, err)
		}
		if ruleReport != nil {
			ruleReports = append(ruleReports, *ruleReport)
		}
	}
	if len(ruleReports) == 0 {
		return nil, nil
	}
	controlReport.RuleReports = ruleReports
	return &controlReport, errs
}

func (opap *OPAProcessor) processRule(rule *reporthandling.PolicyRule) (*reporthandling.RuleReport, error) {
	if ruleWithArmoOpaDependency(rule.Attributes) || !isRuleKubescapeVersionCompatible(rule) {
		return nil, nil
	}

	inputResources, err := reporthandling.RegoResourcesAggregator(rule, getKubernetesObjects(opap.K8SResources, opap.AllResources, rule.Match))
	if err != nil {
		return nil, fmt.Errorf("error getting aggregated k8sObjects: %s", err.Error())
	}
	inputCloudResources, err := reporthandling.RegoResourcesAggregator(rule, getKubernetesObjects(opap.K8SResources, opap.AllResources, rule.DynamicMatch))
	inputResources = append(inputResources, inputCloudResources...)
	if err != nil {
		return nil, fmt.Errorf("error getting aggregated k8sObjects: %s", err.Error())
	}
	inputRawResources := workloadinterface.ListMetaToMap(inputResources)

	ruleReport, err := opap.runOPAOnSingleRule(rule, inputRawResources, ruleData)
	if err != nil {
		// ruleReport.RuleStatus.Status = reporthandling.StatusFailed
		ruleReport.RuleStatus.Status = "failure"
		ruleReport.RuleStatus.Message = err.Error()
		glog.Error(err)
	} else {
		ruleReport.RuleStatus.Status = reporthandling.StatusPassed
	}

	// the failed resources are a subgroup of the enumeratedData, so we store the enumeratedData like it was the input data
	enumeratedData, err := opap.enumerateData(rule, inputRawResources)
	if err != nil {
		return nil, err
	}
	inputResources = workloadinterface.ListMapToMeta(enumeratedData)
	ruleReport.ListInputKinds = workloadinterface.ListMetaIDs(inputResources)

	for i := range inputResources {
		opap.AllResources[inputResources[i].GetID()] = inputResources[i]
	}

	failedResources := workloadinterface.ListMapToMeta(ruleReport.GetFailedResources())
	for i := range failedResources {
		if r, ok := opap.AllResources[failedResources[i].GetID()]; !ok {
			opap.AllResources[failedResources[i].GetID()] = r
		}
	}
	warningResources := workloadinterface.ListMapToMeta(ruleReport.GetWarnignResources())
	for i := range warningResources {
		if r, ok := opap.AllResources[warningResources[i].GetID()]; !ok {
			opap.AllResources[warningResources[i].GetID()] = r
		}
	}

	// remove all data from responses, leave only the metadata
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "namespace", "labels"}
	ruleReport.RemoveData(keepFields, keepMetadataFields)

	return &ruleReport, err
}

func (opap *OPAProcessor) runOPAOnSingleRule(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string) (reporthandling.RuleReport, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(rule, k8sObjects, getRuleData)
	default:
		return reporthandling.RuleReport{}, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

func (opap *OPAProcessor) runRegoOnK8s(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string) (reporthandling.RuleReport, error) {
	var errs error
	ruleReport := reporthandling.RuleReport{
		Name: rule.Name,
	}

	// compile modules
	modules, err := getRuleDependencies()
	if err != nil {
		return ruleReport, fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}
	modules[rule.Name] = getRuleData(rule)
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return ruleReport, fmt.Errorf("in 'runRegoOnSingleRule', failed to compile rule, name: %s, reason: %s", rule.Name, err.Error())
	}

	// Eval
	results, err := opap.regoEval(k8sObjects, compiled)
	if err != nil {
		errs = fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}

	if results != nil {
		ruleReport.RuleResponses = append(ruleReport.RuleResponses, results...)
	}
	return ruleReport, errs
}

func (opap *OPAProcessor) regoEval(inputObj []map[string]interface{}, compiledRego *ast.Compiler) ([]reporthandling.RuleResponse, error) {
	store, err := opap.regoDependenciesData.TOStorage() // get store
	if err != nil {
		return nil, err
	}

	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(store),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	results, err := reporthandling.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}

func (opap *OPAProcessor) enumerateData(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) ([]map[string]interface{}, error) {

	if ruleEnumeratorData(rule) == "" {
		return k8sObjects, nil
	}
	ruleReport, err := opap.runOPAOnSingleRule(rule, k8sObjects, ruleEnumeratorData)
	if err != nil {
		return nil, err
	}
	return ruleReport.GetFailedResources(), nil
}

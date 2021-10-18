package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/exceptions"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/score"

	"github.com/armosec/k8s-interface/k8sinterface"

	"github.com/armosec/opa-utils/resources"
	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	uuid "github.com/satori/go.uuid"
)

const ScoreConfigPath = "/resources/config"

var RegoK8sCredentials storage.Store

type OPAProcessorHandler struct {
	processedPolicy *chan *cautils.OPASessionObj
	reportResults   *chan *cautils.OPASessionObj
	// componentConfig    cautils.ComponentConfig
}

type OPAProcessor struct {
	*cautils.OPASessionObj
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj) *OPAProcessor {
	return &OPAProcessor{
		OPASessionObj: sessionObj,
	}
}

func NewOPAProcessorHandler(processedPolicy, reportResults *chan *cautils.OPASessionObj) *OPAProcessorHandler {

	regoDependenciesData := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), cautils.ClusterName)
	store, err := regoDependenciesData.TOStorage()
	if err != nil {
		panic(err)
	}
	RegoK8sCredentials = store

	return &OPAProcessorHandler{
		processedPolicy: processedPolicy,
		reportResults:   reportResults,
	}
}

func (opaHandler *OPAProcessorHandler) ProcessRulesListenner() {

	for {
		opaSessionObj := <-*opaHandler.processedPolicy
		opap := NewOPAProcessor(opaSessionObj)

		// process
		if err := opap.Process(); err != nil {
			fmt.Println(err)
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
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
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

func (opap *OPAProcessor) processFramework(framework *reporthandling.Framework) (*reporthandling.FrameworkReport, error) {
	var errs error

	frameworkReport := reporthandling.FrameworkReport{}
	frameworkReport.Name = framework.Name

	controlReports := []reporthandling.ControlReport{}
	for i := range framework.Controls {
		controlReport, err := opap.processControl(&framework.Controls[i])
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
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
	controlReport.Control_ID = control.Control_ID // TODO: delete when 'id' is deprecated

	controlReport.Name = control.Name
	controlReport.Description = control.Description
	controlReport.Remediation = control.Remediation

	ruleReports := []reporthandling.RuleReport{}
	for i := range control.Rules {
		ruleReport, err := opap.processRule(&control.Rules[i])
		if err != nil {
			errs = fmt.Errorf("%v\n%s", errs, err.Error())
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
	if ruleWithArmoOpaDependency(rule.Attributes) {
		return nil, nil
	}
	k8sObjects := getKubernetesObjects(opap.K8SResources, rule.Match)
	ruleReport, err := opap.runOPAOnSingleRule(rule, k8sObjects)
	if err != nil {
		ruleReport.RuleStatus.Status = "failure"
		ruleReport.RuleStatus.Message = err.Error()
		glog.Error(err)
	} else {
		ruleReport.RuleStatus.Status = "success"
	}
	ruleReport.ListInputResources = k8sObjects
	return &ruleReport, err
}

func (opap *OPAProcessor) runOPAOnSingleRule(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) (reporthandling.RuleReport, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(rule, k8sObjects)
	default:
		return reporthandling.RuleReport{}, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}
func (opap *OPAProcessor) runRegoOnK8s(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) (reporthandling.RuleReport, error) {
	var errs error
	ruleReport := reporthandling.RuleReport{
		Name: rule.Name,
	}

	// compile modules
	modules, err := getRuleDependencies()
	if err != nil {
		return ruleReport, fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}
	modules[rule.Name] = rule.Rule
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
	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(RegoK8sCredentials),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("in 'regoEval', failed to evaluate rule, reason: %s", err.Error())
	}
	results, err := reporthandling.ParseRegoResult(&resultSet)

	// results, err := ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}

func (opap *OPAProcessor) updateScore() {

	if !k8sinterface.ConnectedToCluster {
		return
	}

	// calculate score
	s := score.NewScore(k8sinterface.NewKubernetesApi(), ScoreConfigPath)
	s.Calculate(opap.PostureReport.FrameworkReports)
}

func (opap *OPAProcessor) updateResults() {
	for f := range opap.PostureReport.FrameworkReports {
		// set exceptions
		exceptions.SetFrameworkExceptions(&opap.PostureReport.FrameworkReports[f], opap.Exceptions, cautils.ClusterName)

		// set counters
		reporthandling.SetUniqueResourcesCounter(&opap.PostureReport.FrameworkReports[f])

		// set default score
		reporthandling.SetDefaultScore(&opap.PostureReport.FrameworkReports[f])

		// edit results - remove data

		// TODO - move function to pkg - use RemoveData
		for c := range opap.PostureReport.FrameworkReports[f].ControlReports {
			for r, ruleReport := range opap.PostureReport.FrameworkReports[f].ControlReports[c].RuleReports {
				// editing the responses -> removing duplications, clearing secret data, etc.
				opap.PostureReport.FrameworkReports[f].ControlReports[c].RuleReports[r].RuleResponses = editRuleResponses(ruleReport.RuleResponses)
			}
		}

	}

}

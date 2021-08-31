package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/kubescape/cautils/k8sinterface"

	"github.com/armosec/kubescape/cautils/opapolicy"
	"github.com/armosec/kubescape/cautils/opapolicy/resources"

	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
)

type OPAProcessor struct {
	processedPolicy    *chan *cautils.OPASessionObj
	reportResults      *chan *cautils.OPASessionObj
	regoK8sCredentials storage.Store
}

func NewOPAProcessor(processedPolicy, reportResults *chan *cautils.OPASessionObj) *OPAProcessor {

	regoDependenciesData := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig())
	store, err := regoDependenciesData.TOStorage()
	if err != nil {
		panic(err)
	}
	return &OPAProcessor{
		processedPolicy:    processedPolicy,
		reportResults:      reportResults,
		regoK8sCredentials: store,
	}
}

func (opap *OPAProcessor) ProcessRulesListenner() {
	for {
		// recover
		defer func() {
			if err := recover(); err != nil {
				glog.Errorf("RECOVER in ProcessRulesListenner, reason: %v", err)
			}
		}()
		opaSessionObj := <-*opap.processedPolicy
		go func() {
			if err := opap.ProcessRulesHandler(opaSessionObj); err != nil {
				// opaSessionObj.Reporter.SendError(nil, true, true)
			}
			*opap.reportResults <- opaSessionObj
		}()
	}
}

func (opap *OPAProcessor) ProcessRulesHandler(opaSessionObj *cautils.OPASessionObj) error {
	cautils.ProgressTextDisplay(fmt.Sprintf("Scanning cluster %s", cautils.ClusterName))
	cautils.StartSpinner()
	frameworkReports := []opapolicy.FrameworkReport{}
	var errs error
	for _, framework := range opaSessionObj.Frameworks {
		frameworkReport := opapolicy.FrameworkReport{}
		frameworkReport.Name = framework.Name
		controlReports := []opapolicy.ControlReport{}
		for _, control := range framework.Controls {
			// cautils.SimpleDisplay(os.Stdout, fmt.Sprintf("\033[2K\r%s", control.Name))
			controlReport := opapolicy.ControlReport{}
			controlReport.Name = control.Name
			controlReport.Description = control.Description
			controlReport.Remediation = control.Remediation
			ruleReports := []opapolicy.RuleReport{}
			for _, rule := range control.Rules {
				if ruleWithArmoOpaDependency(rule.Attributes) {
					continue
				}
				k8sObjects := getKubernetesObjects(opaSessionObj.K8SResources, rule.Match)
				ruleReport, err := opap.runOPAOnSingleRule(&rule, k8sObjects)
				if err != nil {
					ruleReport.RuleStatus.Status = "failure"
					ruleReport.RuleStatus.Message = err.Error()
					glog.Error(err)

					errs = fmt.Errorf("%v\n%s", errs, err.Error())
				} else {
					ruleReport.RuleStatus.Status = "success"
				}
				ruleReport.ListInputResources = k8sObjects
				ruleReport.ListInputKinds = listMatchKinds(rule.Match)
				ruleReports = append(ruleReports, ruleReport)
			}
			controlReport.RuleReports = ruleReports
			controlReports = append(controlReports, controlReport)
		}
		frameworkReport.ControlReports = controlReports
		frameworkReports = append(frameworkReports, frameworkReport)
	}

	opaSessionObj.PostureReport.FrameworkReports = frameworkReports
	opaSessionObj.PostureReport.ReportGenerationTime = time.Now().UTC()
	cautils.StopSpinner()
	cautils.SuccessTextDisplay(fmt.Sprintf("Done scanning cluster %s", cautils.ClusterName))
	return errs
}

func (opap *OPAProcessor) runOPAOnSingleRule(rule *opapolicy.PolicyRule, k8sObjects []map[string]interface{}) (opapolicy.RuleReport, error) {
	switch rule.RuleLanguage {
	case opapolicy.RegoLanguage, opapolicy.RegoLanguage2:
		return opap.runRegoOnK8s(rule, k8sObjects)
	default:
		return opapolicy.RuleReport{}, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}
func (opap *OPAProcessor) runRegoOnK8s(rule *opapolicy.PolicyRule, k8sObjects []map[string]interface{}) (opapolicy.RuleReport, error) {
	var errs error
	ruleReport := opapolicy.RuleReport{
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

func (opap *OPAProcessor) regoEval(inputObj []map[string]interface{}, compiledRego *ast.Compiler) ([]opapolicy.RuleResponse, error) {
	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(opap.regoK8sCredentials),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("In 'regoEval', failed to evaluate rule, reason: %s", err.Error())
	}
	results, err := opapolicy.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}

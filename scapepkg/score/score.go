package score

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	// corev1 "k8s.io/api/core/v1"
	k8sinterface "github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

type ControlScoreWeights struct {
	BaseScore                    float32 `json:"baseScore"`
	RuntimeImprovementMultiplier float32 `json:"improvementRatio"`
}

type ScoreUtil struct {
	ResourceTypeScores map[string]float32
	FrameworksScore    map[string]map[string]ControlScoreWeights
	K8SApoObj          *k8sinterface.KubernetesApi
	configPath         string
}

var postureScore *ScoreUtil

func (su *ScoreUtil) Calculate(frameworksReports []opapolicy.FrameworkReport) error {
	for i := range frameworksReports {
		su.CalculateFrameworkScore(&frameworksReports[i])
	}

	return nil
}

func (su *ScoreUtil) CalculateFrameworkScore(framework *opapolicy.FrameworkReport) error {
	for i := range framework.ControlReports {
		framework.WCSScore += su.ControlScore(&framework.ControlReports[i], framework.Name)
		framework.Score += framework.ControlReports[i].Score
		framework.ARMOImprovement += framework.ControlReports[i].ARMOImprovement
	}
	if framework.WCSScore > 0 {
		framework.Score = (framework.Score * 100) / framework.WCSScore
		framework.ARMOImprovement = (framework.ARMOImprovement * 100) / framework.WCSScore
	}

	return fmt.Errorf("unable to calculate score for framework %s due to bad wcs score", framework.Name)

}

/*
daemonset: daemonsetscore*#nodes
workloads: if replicas:
             replicascore*workloadkindscore*#replicas
           else:
		     regular

*/
func (su *ScoreUtil) resourceRules(resources []map[string]interface{}) float32 {
	var weight float32 = 0

	for _, v := range resources {
		var score float32 = 0
		wl := k8sinterface.NewWorkloadObj(v)
		kind := ""
		if wl != nil {
			kind = strings.ToLower(wl.GetKind())
			replicas := wl.GetReplicas()
			score = su.ResourceTypeScores[kind]
			if replicas > 1 {
				score *= su.ResourceTypeScores["replicaset"] * float32(replicas)
			}

		} else {
			epsilon := float32(0.00001)
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			kind = keys[0]
			score = su.ResourceTypeScores[kind]
			if score == 0.0 || (score > -1*epsilon && score < epsilon) {
				score = 1
			}
		}

		if kind == "daemonset" {
			b, err := json.Marshal(v)
			if err == nil {
				dmnset := appsv1.DaemonSet{}
				json.Unmarshal(b, &dmnset)
				score *= float32(dmnset.Status.DesiredNumberScheduled)
			}
		}
		weight += score
	}

	return weight
}

func (su *ScoreUtil) externalResourceConverter(rscs map[string]interface{}) []map[string]interface{} {
	resources := make([]map[string]interface{}, 0)
	for atype, v := range rscs {
		resources = append(resources, map[string]interface{}{atype: v})
	}
	return resources
}

/*
ControlScore:
@input:
ctrlReport - opapolicy.ControlReport object, must contain down the line the Input resources and the output resources
frameworkName - calculate this control according to a given framework weights

ctrl.score = baseScore * SUM_resource (resourceWeight*min(#replicas*replicaweight,1)(nodes if daemonset)

returns control score ***for the input resources***

*/
func (su *ScoreUtil) ControlScore(ctrlReport *opapolicy.ControlReport, frameworkName string) float32 {

	aggregatedInputs := make([]map[string]interface{}, 0)
	aggregatedResponses := make([]map[string]interface{}, 0)
	for _, ruleReport := range ctrlReport.RuleReports {
		status, _, _ := ruleReport.GetRuleStatus()
		if status != "warning" {
			for _, ruleResponse := range ruleReport.RuleResponses {
				aggregatedResponses = append(aggregatedResponses, ruleResponse.AlertObject.K8SApiObjects...)
				aggregatedResponses = append(aggregatedResponses, su.externalResourceConverter(ruleResponse.AlertObject.ExternalObjects)...)
			}
		}

		aggregatedInputs = append(aggregatedInputs, ruleReport.ListInputResources...)

	}
	improvementRatio := float32(1)
	if ctrls, isOk := su.FrameworksScore[frameworkName]; isOk {
		if scoreobj, isOk2 := ctrls[ctrlReport.Name]; isOk2 {
			ctrlReport.BaseScore = scoreobj.BaseScore
			improvementRatio -= scoreobj.RuntimeImprovementMultiplier
		}
	} else {
		ctrlReport.BaseScore = 1.0
	}

	ctrlReport.Score = ctrlReport.BaseScore * su.resourceRules(aggregatedResponses)
	ctrlReport.ARMOImprovement = ctrlReport.Score * improvementRatio

	return ctrlReport.BaseScore * su.resourceRules(aggregatedInputs)

}

func getPostureFrameworksScores(weightPath string) map[string]map[string]ControlScoreWeights {
	if len(weightPath) != 0 {
		weightPath = weightPath + "/"
	}
	frameworksScoreMap := make(map[string]map[string]ControlScoreWeights)
	dat, err := ioutil.ReadFile(weightPath + "frameworkdict.json")
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(dat, &frameworksScoreMap); err != nil {
		return nil
	}

	return frameworksScoreMap

}

func getPostureResourceScores(weightPath string) map[string]float32 {
	if len(weightPath) != 0 {
		weightPath = weightPath + "/"
	}
	resourceScoreMap := make(map[string]float32)
	dat, err := ioutil.ReadFile(weightPath + "resourcesdict.json")
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(dat, &resourceScoreMap); err != nil {
		return nil
	}

	return resourceScoreMap

}

func NewScore(k8sapiobj *k8sinterface.KubernetesApi, configPath string) *ScoreUtil {
	if postureScore == nil {

		postureScore = &ScoreUtil{
			ResourceTypeScores: getPostureResourceScores(configPath),
			FrameworksScore:    getPostureFrameworksScores(configPath),
			configPath:         configPath,
		}

	}

	return postureScore
}

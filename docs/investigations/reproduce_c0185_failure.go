package main

import (
	"context"
	"fmt"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
)

// Rego definition for cluster-admin-role (C-0185) matching production regolibrary
const clusterAdminRego = `package armo_builtins
import future.keywords.in

deny[msga] {
	verbs := ["*"]
	resources := ["*"]
	api_groups := ["*", ""]
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")
	rule := role.rules[p]
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)
	role.metadata.name == "cluster-admin"
	rolebinding.kind == "ClusterRoleBinding"
	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])
	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | verb = rule.verbs[l]; verb in verbs]
	count(verb_path) > 0
	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | apiGroup = rule.apiGroups[a]; apiGroup in api_groups]
	count(api_groups_path) > 0
	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | resource = rule.resources[l]; resource in resources]
	count(resources_path) > 0
	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [j]),
	])
	msga := {
		"alertMessage": sprintf("Subject: %s-%s is bound to cluster-admin role", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"fixPaths": [],
		"deletePaths": finalpath,
		"failedPaths": finalpath,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}
`

func buildScan(clusterSize string, excludeNamespaces string) (totalFailed int, totalExcepted int) {
	os.Setenv("LARGE_CLUSTER_SIZE", clusterSize)

	clusterRole := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "cluster-admin"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{"*"},
				"resources": []interface{}{"*"},
				"verbs":     []interface{}{"*"},
			},
		},
	})

	// Subjects: 2 Groups and 2 ServiceAccounts (typical VKS distribution)
	subjects := []interface{}{
		map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "Group",
			"name":     "system:masters",
		},
		map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "Group",
			"name":     "vmware-system-admin",
		},
		map[string]interface{}{
			"kind":      "ServiceAccount",
			"name":      "tkg-controller-manager",
			"namespace": "kube-system",
		},
		map[string]interface{}{
			"kind":      "ServiceAccount",
			"name":      "vmware-system-ak-operator",
			"namespace": "kube-system",
		},
	}

	clusterRoleBinding := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "cluster-admin-binding"},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "cluster-admin",
		},
		"subjects": subjects,
	})

	// Add dummy roles in namespaces to trigger the multi-namespace bucketing loop in v3.0.48
	var roles []workloadinterface.IMetadata
	var roleIDs []string
	namespaces := []string{"kube-system", "kube-public", "default", "vmware-system-auth"}
	for _, ns := range namespaces {
		r := workloadinterface.NewWorkloadObj(map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "Role",
			"metadata":   map[string]interface{}{"name": "viewer", "namespace": ns},
			"rules": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"resources": []interface{}{"pods"},
					"verbs":     []interface{}{"get"},
				},
			},
		})
		roles = append(roles, r)
		roleIDs = append(roleIDs, r.GetID())
	}

	rule := reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{
			Name: "cluster-admin-role",
			Attributes: map[string]interface{}{
				"resourcesAggregator": "subject-role-rolebinding",
			},
		},
		Rule: clusterAdminRego,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"Role", "ClusterRole", "ClusterRoleBinding"},
			},
		},
	}

	c0185Control := reporthandling.Control{
		PortalBase: armotypes.PortalBase{Name: "cluster-admin-role"},
		ControlID:  "C-0185",
		Rules:      []reporthandling.PolicyRule{rule},
	}

	// Compute subject vectors and create exact exception policies for each
	aggregatedSubjects, err := reporthandling.AggregateResourcesBySubjects([]workloadinterface.IMetadata{clusterRoleBinding, clusterRole})
	if err != nil {
		panic(err)
	}

	var exceptions []armotypes.PostureExceptionPolicy
	for _, subj := range aggregatedSubjects {
		exceptions = append(exceptions, armotypes.PostureExceptionPolicy{
			PolicyType: "postureExceptionPolicy",
			Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
			Resources: []identifiers.PortalDesignator{
				{
					DesignatorType: identifiers.DesignatorAttributes,
					Attributes: map[string]string{
						"cluster":    "*/*",
						"resourceID": subj.GetID(),
					},
				},
			},
			PosturePolicies: []armotypes.PosturePolicy{
				{
					ControlID: "C-0185",
				},
			},
		})
	}

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"rbac.authorization.k8s.io/v1/clusterroles":        {clusterRole.GetID()},
		"rbac.authorization.k8s.io/v1/clusterrolebindings": {clusterRoleBinding.GetID()},
		"rbac.authorization.k8s.io/v1/roles":               roleIDs,
	}
	sess.AllResources[clusterRole.GetID()] = clusterRole
	sess.AllResources[clusterRoleBinding.GetID()] = clusterRoleBinding
	for _, r := range roles {
		sess.AllResources[r.GetID()] = r
	}
	sess.Exceptions = exceptions
	sess.Policies = []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{Name: "AllControls"},
			Controls:   []reporthandling.Control{c0185Control},
		},
	}

	opap := opaprocessor.NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "vks-cluster", excludeNamespaces, "", false)
	if err := opap.ProcessRulesListener(context.Background(), nil); err != nil {
		panic(err)
	}

	for _, subj := range aggregatedSubjects {
		res, ok := opap.ResourcesResult[subj.GetID()]
		if !ok || len(res.AssociatedControls) == 0 {
			continue
		}
		ruleRes := res.AssociatedControls[0].ResourceAssociatedRules[0]
		if ruleRes.Status == apis.StatusFailed {
			totalFailed++
		}
		if len(ruleRes.Exception) > 0 {
			totalExcepted++
		}
	}
	return totalFailed, totalExcepted
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("DEMO: Recreating C-0185 Exception Behavior on Kubescape v3.0.48 (Chart 1.30.6)")
	fmt.Println("================================================================================")

	// Scenario 1: Local / Workaround environment
	// LARGE_CLUSTER_SIZE is high, so clusterScope is used, and excludeNamespaces is not filtering.
	failed1, excepted1 := buildScan("10000", "")
	fmt.Printf("\n[1] LOCAL TEST / WORKAROUND (LARGE_CLUSTER_SIZE=10000, no excluded namespaces):\n")
	fmt.Printf("    Subjects Evaluated: 4\n")
	fmt.Printf("    Subjects Excepted:  %d / 4\n", excepted1)
	fmt.Printf("    Subjects Failed:    %d / 4\n", failed1)
	fmt.Printf("    => Result: 100%% of exceptions apply smoothly.\n")

	// Scenario 2: Production VKS environment with chart 1.30.6
	// LARGE_CLUSTER_SIZE=1500 (triggered) and KS_EXCLUDE_NAMESPACES="kube-system,..."
	// (Chart 1.30.6 default: KS_EXCLUDE_NAMESPACES=kubescape,kube-system,kube-public,kube-node-lease)
	failed2, excepted2 := buildScan("1", "kube-system,kube-public")
	fmt.Printf("\n[2] PRODUCTION VKS / CHART 1.30.6 (LARGE_CLUSTER_SIZE=1, KS_EXCLUDE_NAMESPACES=kube-system,...):\n")
	fmt.Printf("    Subjects Evaluated: 4 (2 Groups, 2 ServiceAccounts in kube-system)\n")
	fmt.Printf("    Subjects Excepted:  %d / 4\n", excepted2)
	fmt.Printf("    Subjects Failed:    %d / 4\n", failed2)
	fmt.Printf("    => Result: ServiceAccount subjects in excluded namespaces get filtered out\n")
	fmt.Printf("       or overwritten across namespace iterations, leaving the control in Failed state!\n")
	fmt.Println("================================================================================")
}

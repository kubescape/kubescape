package opapolicy

import (
	"time"

	armotypes "github.com/armosec/kubescape/cautils/armotypes"
)

// Mock A
var (
	AMockCustomerGUID  = "5d817063-096f-4d91-b39b-8665240080af"
	AMockJobID         = "36b6f9e1-3b63-4628-994d-cbe16f81e9c7"
	AMockReportID      = "2c31e4da-c6fe-440d-9b8a-785b80c8576a"
	AMockClusterName   = "clusterA"
	AMockFrameworkName = "testFrameworkA"
	AMockControlName   = "testControlA"
	AMockRuleName      = "testRuleA"
	AMockPortalBase    = *armotypes.MockPortalBase(AMockCustomerGUID, "", nil)
)

func MockRuleResponseA() *RuleResponse {
	return &RuleResponse{
		AlertMessage: "test alert message A",
		AlertScore:   0,
		Rulename:     AMockRuleName,
		PackageName:  "test.package.name.A",
		Context:      []string{},
	}
}

func MockFrameworkReportA() *FrameworkReport {
	return &FrameworkReport{
		Name: AMockFrameworkName,
		ControlReports: []ControlReport{
			{
				Name: AMockControlName,
				RuleReports: []RuleReport{
					{
						Name:        AMockRuleName,
						Remediation: "remove privilegedContainer: True flag from your pod spec",
						RuleResponses: []RuleResponse{
							*MockRuleResponseA(),
						},
					},
				},
			},
		},
	}
}

func MockPostureReportA() *PostureReport {
	return &PostureReport{
		CustomerGUID:         AMockCustomerGUID,
		ClusterName:          AMockClusterName,
		ReportID:             AMockReportID,
		JobID:                AMockJobID,
		ReportGenerationTime: time.Now().UTC(),
		FrameworkReports:     []FrameworkReport{*MockFrameworkReportA()},
	}
}

func MockFrameworkA() *Framework {
	return &Framework{
		PortalBase:   *armotypes.MockPortalBase("aaaaaaaa-096f-4d91-b39b-8665240080af", AMockFrameworkName, nil),
		CreationTime: "",
		Description:  "mock framework descryption",
		Controls: []Control{
			{
				PortalBase: *armotypes.MockPortalBase("aaaaaaaa-aaaa-4d91-b39b-8665240080af", AMockControlName, nil),
				Rules: []PolicyRule{
					*MockRuleA(),
				},
			},
		},
	}
}

func MockRuleUntrustedRegistries() *PolicyRule {
	return &PolicyRule{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-aaaa-aaaa-b39b-8665240080af", AMockControlName, nil),
		Rule: `
package armo_builtins
# Check for images from blacklisted repos

untrusted_registries(z) = x {
	x := ["015253967648.dkr.ecr.eu-central-1.amazonaws.com/"]	
}

public_registries(z) = y{
	y := ["quay.io/kiali/","quay.io/datawire/","quay.io/keycloak/","quay.io/bitnami/"]
}

untrustedImageRepo[msga] {
	pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[_]
	image := container.image
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	selfLink := pod.metadata.selfLink
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' in [%s] comes from untrusted registry", [image, containerName, selfLink]),
		"alert": true,
		"prevent": false,
		"alertScore": 2,
		"alertObject": [{"pod":pod}]
	}
}

untrustedImageRepo[msga] {
    pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[_]
	image := container.image
    repo_prefix := public_registries(image)[_]
	startswith(pod, repo_prefix)
	selfLink := input.metadata.selfLink
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' in [%s] comes from public registry", [image, containerName, selfLink]),
		"alert": true,
		"prevent": false,
		"alertScore": 1,
		"alertObject": [{"pod":pod}]
	}
}
		`,
		RuleLanguage: RegoLanguage,
		Match: []RuleMatchObjects{
			{
				APIVersions: []string{"v1"},
				APIGroups:   []string{"*"},
				Resources:   []string{"pods"},
			},
		},
		RuleDependencies: []RuleDependency{
			{
				PackageName: "kubernetes.api.client",
			},
		},
	}
}

func MockRuleA() *PolicyRule {
	return &PolicyRule{
		PortalBase:   *armotypes.MockPortalBase("aaaaaaaa-aaaa-aaaa-b39b-8665240080af", AMockControlName, nil),
		Rule:         MockRegoPrivilegedPods(), //
		RuleLanguage: RegoLanguage,
		Match: []RuleMatchObjects{
			{
				APIVersions: []string{"v1"},
				APIGroups:   []string{"*"},
				Resources:   []string{"pods"},
			},
		},
		RuleDependencies: []RuleDependency{
			{
				PackageName: "kubernetes.api.client",
			},
		},
	}
}

func MockRuleB() *PolicyRule {
	return &PolicyRule{
		PortalBase:   *armotypes.MockPortalBase("bbbbbbbb-aaaa-aaaa-b39b-8665240080af", AMockControlName, nil),
		Rule:         MockExternalFacingService(), //
		RuleLanguage: RegoLanguage,
		Match: []RuleMatchObjects{
			{
				APIVersions: []string{"v1"},
				APIGroups:   []string{""},
				Resources:   []string{"pods"},
			},
		},
		RuleDependencies: []RuleDependency{
			{
				PackageName: "kubernetes.api.client",
			},
		},
	}
}

func MockPolicyNotificationA() *PolicyNotification {
	return &PolicyNotification{
		NotificationType: TypeExecPostureScan,
		ReportID:         AMockReportID,
		JobID:            AMockJobID,
		Designators:      armotypes.PortalDesignator{},
		Rules: []PolicyIdentifier{
			{
				Kind: KindFramework,
				Name: AMockFrameworkName,
			}},
	}
}

func MockTemp() string {
	return `
	package armo_builtins
	import data.kubernetes.api.client as client
	deny[msga] {
		#object := input[_]
		object := client.query_all("pods")
		obj := object.body.items[_]
		msga := {
			"packagename": "armo_builtins",
			"alertMessage": "found object",
			"alertScore": 3,
			"alertObject": {"object": obj},
		}
	}
	`
}

func MockRegoPrivilegedPods() string {
	return `package armo_builtins

	import data.kubernetes.api.client as client

	# Deny mutating action unless user is in group owning the resource
	
	#privileged pods
	deny[msga] {
	   
		pod := input[_]
		containers := pod.spec.containers[_]
		containers.securityContext.privileged == true
		msga := {
			"packagename": "armo_builtins",
			"alertMessage": sprintf("the following pods are defined as privileged: %v", [pod]),
			"alertScore": 3,
			"alertObject": pod,
		}
	}
	
	#handles majority of workload resources
	deny[msga] {
		wl := input[_]
		spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
		spec_template_spec_patterns[wl.kind]
		containers := wl.spec.template.spec.containers[_]
		containers.securityContext.privileged == true
		msga := {
			"packagename": "armo_builtins",
			"alertMessage": sprintf("the following workloads are defined as privileged: %v", [wl]),
			"alertScore": 3,
			"alertObject": wl,
		}
	}
	
	#handles cronjob
	deny[msga] {
		wl := input[_]
		wl.kind == "CronJob"
		containers := wl.spec.jobTemplate.spec.template.spec.containers[_]
		containers.securityContext.privileged == true
		msga := {
			"packagename": "armo_builtins",
			"alertMessage": sprintf("the following cronjobs are defined as privileged: %v", [wl]),
			"alertScore": 3,
			"alertObject": wl,
		}
	}
	`
}

func MockExternalFacingService() string {
	return "\n\tpackage armo_builtins\n\n\timport data.kubernetes.api.client as client\n\timport data.cautils as cautils\n\ndeny[msga] {\n\n\twl := input[_]\n\tcluster_resource := client.query_all(\n\t\t\"services\"\n\t)\n\n\tlabels := wl.metadata.labels\n\tfiltered_labels := json.remove(labels, [\"pod-template-hash\"])\n    \n#service := cluster_resource.body.items[i]\nservices := [svc | cluster_resource.body.items[i].metadata.namespace == wl.metadata.namespace; svc := cluster_resource.body.items[i]]\nservice := services[_]\nnp_or_lb := {\"NodePort\", \"LoadBalancer\"}\nnp_or_lb[service.spec.type]\ncautils.is_subobject(service.spec.selector,filtered_labels)\n\n    msga := {\n\t\t\"alertMessage\": sprintf(\"%v pod %v  expose external facing service: %v\",[wl.metadata.namespace, wl.metadata.name, service.metadata.name]),\n\t\t\"alertScore\": 2,\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertObject\": {\"srvc\":service}\n\t}\n}\n\t"
}
func GetRuntimePods() string {
	return `
    package armo_builtins

    import data.kubernetes.api.client as client
    

deny[msga] {

    
    cluster_resource := client.query_all(
      "pods"
  )

	pod := cluster_resource.body.items[i]
    msga := {
        "alertMessage": "got something",
        "alertScore": 2,
        "packagename": "armo_builtins",
        "alertObject": {"pod": pod}
    }
}
    
    `
}

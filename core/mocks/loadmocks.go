package mocks

import (
	"encoding/json"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
)

var mockControl_0006 = `{"guid":"","name":"HostPath mount","attributes":{},"id":"C-0048","controlID":"C-0048","creationTime":"","description":"Mounting host directory to the container can be abused to get access to sensitive data and gain persistence on the host machine.","remediation":"Refrain from using host path mount.","rules":[{"guid":"","name":"alert-rw-hostpath","attributes":{"m$K8sThreatMatrix":"Persistence::Writable hostPath mount, Lateral Movement::Writable volume mounts on the host"},"creationTime":"","rule":"package armo_builtins\n\n# input: pod\n# apiversion: v1\n# does: returns hostPath volumes\n\ndeny[msga] {\n    pod := input[_]\n    pod.kind == \"Pod\"\n    volumes := pod.spec.volumes\n    volume := volumes[_]\n    volume.hostPath\n\tcontainer := pod.spec.containers[i]\n\tvolumeMount := container.volumeMounts[k]\n\tvolumeMount.name == volume.name\n\tbegginingOfPath := \"spec.\"\n\tresult := isRWMount(volumeMount, begginingOfPath,  i, k)\n\n    podname := pod.metadata.name\n\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"pod: %v has: %v as hostPath volume\", [podname, volume.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [pod]\n\t\t}\n\t}\n}\n\n#handles majority of workload resources\ndeny[msga] {\n\twl := input[_]\n\tspec_template_spec_patterns := {\"Deployment\",\"ReplicaSet\",\"DaemonSet\",\"StatefulSet\",\"Job\"}\n\tspec_template_spec_patterns[wl.kind]\n    volumes := wl.spec.template.spec.volumes\n    volume := volumes[_]\n    volume.hostPath\n\tcontainer := wl.spec.template.spec.containers[i]\n\tvolumeMount := container.volumeMounts[k]\n\tvolumeMount.name == volume.name\n\tbegginingOfPath := \"spec.template.spec.\"\n\tresult := isRWMount(volumeMount, begginingOfPath,  i, k)\n\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"%v: %v has: %v as hostPath volume\", [wl.kind, wl.metadata.name, volume.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t\n\t}\n}\n\n#handles CronJobs\ndeny[msga] {\n\twl := input[_]\n\twl.kind == \"CronJob\"\n    volumes := wl.spec.jobTemplate.spec.template.spec.volumes\n    volume := volumes[_]\n    volume.hostPath\n\n\tcontainer = wl.spec.jobTemplate.spec.template.spec.containers[i]\n\tvolumeMount := container.volumeMounts[k]\n\tvolumeMount.name == volume.name\n\tbegginingOfPath := \"spec.jobTemplate.spec.template.spec.\"\n\tresult := isRWMount(volumeMount, begginingOfPath,  i, k)\n\n\tmsga := {\n\t\"alertMessage\": sprintf(\"%v: %v has: %v as hostPath volume\", [wl.kind, wl.metadata.name, volume.name]),\n\t\"packagename\": \"armo_builtins\",\n\t\"alertScore\": 7,\n\t\"failedPaths\": [result],\n\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\nisRWMount(mount, begginingOfPath,  i, k) = path {\n not mount.readOnly == true\n not mount.readOnly == false\n path = \"\"\n}\nisRWMount(mount, begginingOfPath,  i, k) = path {\n  mount.readOnly == false\n  path = sprintf(\"%vcontainers[%v].volumeMounts[%v].readOnly\", [begginingOfPath, format_int(i, 10), format_int(k, 10)])\n} ","resourceEnumerator":"","ruleLanguage":"Rego","match":[{"apiGroups":["*"],"apiVersions":["*"],"resources":["Deployment","ReplicaSet","DaemonSet","StatefulSet","Job","CronJob","Pod"]}],"ruleDependencies":[{"packageName":"cautils"},{"packageName":"kubernetes.api.client"}],"configInputs":null,"controlConfigInputs":null,"description":"determines if any workload contains a hostPath volume with rw permissions","remediation":"Set the readOnly field of the mount to true","ruleQuery":""}],"rulesIDs":[""],"baseScore":6}`

var mockControl_0044 = `{"guid":"","name":"Container hostPort","attributes":{},"id":"C-0044","controlID":"C-0044","creationTime":"","description":"Configuring hostPort limits you to a particular port, and if any two workloads that specify the same HostPort they cannot be deployed to the same node. Therefore, if the number of replica of such workload is higher than the number of nodes, the deployment will fail.","remediation":"Avoid usage of hostPort unless it is absolutely necessary. Use NodePort / ClusterIP instead.","rules":[{"guid":"","name":"container-hostPort","attributes":{},"creationTime":"","rule":"package armo_builtins\n\n\n# Fails if pod has container with hostPort\ndeny[msga] {\n    pod := input[_]\n    pod.kind == \"Pod\"\n    container := pod.spec.containers[i]\n\tbegginingOfPath := \"spec.\"\n\tpath := isHostPort(container, i, begginingOfPath)\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"Container: %v has Host-port\", [ container.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": path,\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [pod]\n\t\t}\n\t}\n}\n\n# Fails if workload has container with hostPort\ndeny[msga] {\n    wl := input[_]\n\tspec_template_spec_patterns := {\"Deployment\",\"ReplicaSet\",\"DaemonSet\",\"StatefulSet\",\"Job\"}\n\tspec_template_spec_patterns[wl.kind]\n    container := wl.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.template.spec.\"\n    path := isHostPort(container, i, begginingOfPath)\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"Container: %v in %v: %v   has Host-port\", [ container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": path,\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n# Fails if cronjob has container with hostPort\ndeny[msga] {\n  \twl := input[_]\n\twl.kind == \"CronJob\"\n\tcontainer = wl.spec.jobTemplate.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.jobTemplate.spec.template.spec.\"\n    path := isHostPort(container, i, begginingOfPath)\n    msga := {\n\t\t\"alertMessage\": sprintf(\"Container: %v in %v: %v   has Host-port\", [ container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": path,\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n\n\nisHostPort(container, i, begginingOfPath) = path {\n\tpath = [sprintf(\"%vcontainers[%v].ports[%v].hostPort\", [begginingOfPath, format_int(i, 10), format_int(j, 10)]) | port = container.ports[j];  port.hostPort]\n\tcount(path) > 0\n}\n","resourceEnumerator":"","ruleLanguage":"Rego","match":[{"apiGroups":["*"],"apiVersions":["*"],"resources":["Deployment","ReplicaSet","DaemonSet","StatefulSet","Job","Pod","CronJob"]}],"ruleDependencies":[],"configInputs":null,"controlConfigInputs":null,"description":"fails if container has hostPort","remediation":"Make sure you do not configure hostPort for the container, if necessary use NodePort / ClusterIP","ruleQuery":"armo_builtins"}],"rulesIDs":[""],"baseScore":4}`

var mockControl_0013 = `{"guid":"","name":"Non-root containers","attributes":{},"id":"C-0013","controlID":"C-0013","creationTime":"","description":"Potential attackers may gain access to a container and leverage its existing privileges to conduct an attack. Therefore, it is not recommended to deploy containers with root privileges unless it is absolutely necessary. This contol identifies all the Pods running as root or can escalate to root.","remediation":"If your application does not need root privileges, make sure to define the runAsUser or runAsGroup under the PodSecurityContext and use user ID 1000 or higher. Do not turn on allowPrivlegeEscalation bit and make sure runAsNonRoot is true.","rules":[{"guid":"","name":"non-root-containers","attributes":{},"creationTime":"","rule":"package armo_builtins\n\n\n# Fails if pod has container  configured to run as root\ndeny[msga] {\n    pod := input[_]\n    pod.kind == \"Pod\"\n\tcontainer := pod.spec.containers[i]\n\tbegginingOfPath := \"spec.\"\n    result := isRootContainer(container, i, begginingOfPath)\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"container: %v in pod: %v  may run as root\", [container.name, pod.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [pod]\n\t\t}\n\t}\n}\n\n# Fails if pod has container  configured to run as root\ndeny[msga] {\n    pod := input[_]\n    pod.kind == \"Pod\"\n\tcontainer := pod.spec.containers[i]\n\tbegginingOfPath =\"spec.\"\n    result := isRootPod(pod, container, i, begginingOfPath)\n\tmsga := {\n\t\t\"alertMessage\": sprintf(\"container: %v in pod: %v  may run as root\", [container.name, pod.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [pod]\n\t\t}\n\t}\n}\n\n\n\n# Fails if workload has container configured to run as root\ndeny[msga] {\n    wl := input[_]\n\tspec_template_spec_patterns := {\"Deployment\",\"ReplicaSet\",\"DaemonSet\",\"StatefulSet\",\"Job\"}\n\tspec_template_spec_patterns[wl.kind]\n    container := wl.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.template.spec.\"\n    result := isRootContainer(container, i, begginingOfPath)\n    msga := {\n\t\t\"alertMessage\": sprintf(\"container :%v in %v: %v may run as root\", [container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n# Fails if workload has container configured to run as root\ndeny[msga] {\n    wl := input[_]\n\tspec_template_spec_patterns := {\"Deployment\",\"ReplicaSet\",\"DaemonSet\",\"StatefulSet\",\"Job\"}\n\tspec_template_spec_patterns[wl.kind]\n    container := wl.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.template.spec.\"\n    result := isRootPod(wl.spec.template, container, i, begginingOfPath)\n    msga := {\n\t\t\"alertMessage\": sprintf(\"container :%v in %v: %v may run as root\", [container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n\n# Fails if cronjob has a container configured to run as root\ndeny[msga] {\n\twl := input[_]\n\twl.kind == \"CronJob\"\n\tcontainer = wl.spec.jobTemplate.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.jobTemplate.spec.template.spec.\"\n\tresult := isRootContainer(container, i, begginingOfPath)\n    msga := {\n\t\t\"alertMessage\": sprintf(\"container :%v in %v: %v  may run as root\", [container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n\n\n# Fails if workload has container configured to run as root\ndeny[msga] {\n  \twl := input[_]\n\twl.kind == \"CronJob\"\n\tcontainer = wl.spec.jobTemplate.spec.template.spec.containers[i]\n\tbegginingOfPath := \"spec.jobTemplate.spec.template.spec.\"\n    result := isRootPod(wl.spec.jobTemplate.spec.template, container, i, begginingOfPath)\n    msga := {\n\t\t\"alertMessage\": sprintf(\"container :%v in %v: %v may run as root\", [container.name, wl.kind, wl.metadata.name]),\n\t\t\"packagename\": \"armo_builtins\",\n\t\t\"alertScore\": 7,\n\t\t\"failedPaths\": [result],\n\t\t\"alertObject\": {\n\t\t\t\"k8sApiObjects\": [wl]\n\t\t}\n\t}\n}\n\n\nisRootPod(pod, container, i, begginingOfPath) = path {\n\tpath = \"\"\n    not container.securityContext.runAsUser\n    pod.spec.securityContext.runAsUser == 0\n\tpath = \"spec.securityContext.runAsUser\"\n}\n\nisRootPod(pod, container, i, begginingOfPath) = path {\n\tpath = \"\"\n    not container.securityContext.runAsUser\n\tnot container.securityContext.runAsGroup\n\tnot container.securityContext.runAsNonRoot\n    not pod.spec.securityContext.runAsUser\n\tnot pod.spec.securityContext.runAsGroup\n    pod.spec.securityContext.runAsNonRoot == false\n\tpath = \"spec.securityContext.runAsNonRoot\"\n}\n\nisRootPod(pod, container, i, begginingOfPath) = path {\n\tpath = \"\"\n    not container.securityContext.runAsGroup\n    pod.spec.securityContext.runAsGroup == 0\n\tpath = sprintf(\"%vsecurityContext.runAsGroup\", [begginingOfPath])\n}\n\nisRootPod(pod, container, i, begginingOfPath)= path  {\n\tpath = \"\"\n\tnot pod.spec.securityContext.runAsGroup\n\tnot pod.spec.securityContext.runAsUser\n   \tcontainer.securityContext.runAsNonRoot == false\n\tpath = sprintf(\"%vcontainers[%v].securityContext.runAsNonRoot\", [begginingOfPath, format_int(i, 10)])\n}\n\nisRootContainer(container, i, begginingOfPath) = path  {\n\tpath = \"\"\n    container.securityContext.runAsUser == 0\n\tpath = sprintf(\"%vcontainers[%v].securityContext.runAsUser\", [begginingOfPath, format_int(i, 10)])\n}\n\nisRootContainer(container, i, begginingOfPath) = path  {\n\tpath = \"\"\n     container.securityContext.runAsGroup == 0\n\t path = sprintf(\"%vcontainers[%v].securityContext.runAsGroup\", [begginingOfPath, format_int(i, 10)])\n}","resourceEnumerator":"","ruleLanguage":"Rego","match":[{"apiGroups":["*"],"apiVersions":["*"],"resources":["Deployment","ReplicaSet","DaemonSet","StatefulSet","Job","Pod","CronJob"]}],"ruleDependencies":[],"configInputs":null,"controlConfigInputs":null,"description":"fails if container can run as root","remediation":"Make sure that the user/group in the securityContext of pod/container is set to an id less than 1000, or the runAsNonRoot flag is set to true. Also make sure that the allowPrivilegeEscalation field is set to false","ruleQuery":"armo_builtins"}],"rulesIDs":[""],"baseScore":6}`

var mockPrivilegedDevelopment = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"privileged-deployment","labels":{"app":"nginx"}},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"name":"nginx","image":"nginx:1.18.0","ports":[{"containerPort":80}],"securityContext":{"privileged":true}}]}}}}`

var mockHostpathDevelopment = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"hostpath-deployment"},"spec":{"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"serviceAccountName":"default","terminationGracePeriodSeconds":5,"containers":[{"name":"server","image":"nginx","ports":[{"containerPort":9555}],"env":[{"name":"PORT","value":"9555"}],"volumeMounts":[{"mountPath":"/test-pd","name":"test-volume"}]}],"volumes":[{"name":"test-volume","hostPath":{"path":"/data","type":"Directory"}}]}}}}`

// MockFramework_0013 mock control 0013 - Non-root containers
func MockFramework_0013() *reporthandling.Framework {
	fw := &reporthandling.Framework{
		PortalBase: armotypes.PortalBase{
			Name: "framework-0013",
		},
	}
	c := &reporthandling.Control{}
	json.Unmarshal([]byte(mockControl_0013), c)
	fw.Controls = []reporthandling.Control{*c}
	return fw
}

// MockFramework_0006_0013 mock control 0013 and control 0006 - "Non-root containers" and "HostPath mount"
func MockFramework_0006_0013() *reporthandling.Framework {
	fw := &reporthandling.Framework{
		PortalBase: armotypes.PortalBase{
			Name: "framework-0006-0013",
		},
	}
	c06 := &reporthandling.Control{ScanningScope: &reporthandling.ScanningScope{
		Matches: []reporthandling.ScanningScopeType{
			reporthandling.ScopeCluster,
		},
	}}
	json.Unmarshal([]byte(mockControl_0006), c06)
	c13 := &reporthandling.Control{ScanningScope: &reporthandling.ScanningScope{
		Matches: []reporthandling.ScanningScopeType{
			reporthandling.ScopeCluster,
		},
	}}
	json.Unmarshal([]byte(mockControl_0013), c13)
	fw.Controls = []reporthandling.Control{*c06, *c13}
	return fw
}

// MockFramework_0044 mock control 0044 - "Container hostPort"
func MockFramework_0044() *reporthandling.Framework {
	fw := &reporthandling.Framework{
		PortalBase: armotypes.PortalBase{
			Name: "framework-0044",
		},
	}
	c44 := &reporthandling.Control{ScanningScope: &reporthandling.ScanningScope{
		Matches: []reporthandling.ScanningScopeType{
			reporthandling.ScopeCluster,
		},
	}}
	json.Unmarshal([]byte(mockControl_0044), c44)

	fw.Controls = []reporthandling.Control{*c44}
	return fw
}
func MockDevelopmentPrivileged() workloadinterface.IMetadata {
	w, _ := workloadinterface.NewWorkload([]byte(mockPrivilegedDevelopment))
	return w
}

func MockDevelopmentWithHostpath() workloadinterface.IMetadata {
	w, _ := workloadinterface.NewWorkload([]byte(mockHostpathDevelopment))
	return w
}

func MockExceptionAllKinds(policy *armotypes.PosturePolicy) *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{*policy},
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{
			{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes: map[string]string{
					identifiers.AttributeKind: ".*",
				},
			},
		},
	}
}

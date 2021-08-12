package k8sinterface

import (
	"encoding/json"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func V1KubeSystemNamespaceMock() *unstructured.UnstructuredList {
	podsList := `
	{"apiVersion":"v1","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"cyberarmor.jobs":"{\"jobID\":\"\",\"parentJobID\":\"\",\"actionID\":\"4\"}","cyberarmor.last-update":"07-04-2021 19:17:56","cyberarmor.status":"Patched","cyberarmor.wlid":"wlid://cluster-openrasty_seal-7fvz/namespace-default/deployment-nginx-deployment","wlid":"wlid://cluster-openrasty_seal-7fvz/namespace-default/deployment-nginx-deployment"},"creationTimestamp":"2021-04-08T06:18:15Z","generateName":"nginx-deployment-dd485bc9-","labels":{"app":"nginx","cyberarmor":"Patched","pod-template-hash":"dd485bc9"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:cyberarmor.jobs":{},"f:cyberarmor.last-update":{},"f:cyberarmor.status":{},"f:cyberarmor.wlid":{},"f:wlid":{}},"f:generateName":{},"f:labels":{".":{},"f:app":{},"f:cyberarmor":{},"f:pod-template-hash":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"b223826d-3aa9-4a9d-b057-2736a8800d71\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"nginx\"}":{".":{},"f:env":{".":{},"k:{\"name\":\"CAA_CONTAINER_IMAGE_NAME\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_CONTAINER_NAME\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_ENABLE_DISCOVERY\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_HOME\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_LOADNAMES\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_NOTIFICATION_SERVER\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_ORACLE_SERVER\"}":{".":{},"f:name":{},"f:value":{}},"k:{\"name\":\"CAA_POD_NAME\"}":{".":{},"f:name":{},"f:valueFrom":{".":{},"f:fieldRef":{".":{},"f:apiVersion":{},"f:fieldPath":{}}}},"k:{\"name\":\"CAA_POD_NAMESPACE\"}":{".":{},"f:name":{},"f:valueFrom":{".":{},"f:fieldRef":{".":{},"f:apiVersion":{},"f:fieldPath":{}}}},"k:{\"name\":\"LD_PRELOAD\"}":{".":{},"f:name":{},"f:value":{}}},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:ports":{".":{},"k:{\"containerPort\":80,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:protocol":{}}},"f:resources":{},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{},"f:volumes":{".":{},"k:{\"name\":\"caa-home-vol\"}":{".":{},"f:emptyDir":{},"f:name":{}}}}},"manager":"kube-controller-manager","operation":"Update","time":"2021-04-09T09:29:24Z"},{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:initContainerStatuses":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"172.17.0.13\"}":{".":{},"f:ip":{}}},"f:startTime":{}}},"manager":"kubelet","operation":"Update","time":"2021-04-12T04:44:06Z"}],"name":"nginx-deployment-dd485bc9-bfgnh","namespace":"default","ownerReferences":[{"apiVersion":"apps/v1","blockOwnerDeletion":true,"controller":true,"kind":"ReplicaSet","name":"nginx-deployment-dd485bc9","uid":"b223826d-3aa9-4a9d-b057-2736a8800d71"}],"resourceVersion":"612143","uid":"8966bf5a-80e8-4b3a-9c0b-ab9091d3f478"},"spec":{"containers":[{"env":[{"name":"CAA_NOTIFICATION_SERVER","value":"http://10.110.208.9:8001"},{"name":"CAA_CONTAINER_NAME","value":"nginx"},{"name":"LD_PRELOAD","value":"/etc/cyberarmor/libcaa.so"},{"name":"CAA_POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"CAA_HOME","value":"/etc/cyberarmor"},{"name":"CAA_ORACLE_SERVER","value":"http://10.102.233.40:4000"},{"name":"CAA_ENABLE_DISCOVERY","value":"true"},{"name":"CAA_CONTAINER_IMAGE_NAME","value":"nginx:1.14.2"},{"name":"CAA_POD_NAMESPACE","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"}}},{"name":"CAA_LOADNAMES","value":"*"},{"name":"CAA_GUID","value":"37ad7bc4-dbdf-48fc-86b5-6d4fdae784ad"}],"image":"debian:10.9","imagePullPolicy":"IfNotPresent","name":"nginx","ports":[{"containerPort":80,"protocol":"TCP"}],"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"default-token-gpl5r","readOnly":true},{"mountPath":"/etc/cyberarmor","name":"caa-home-vol","subPath":"nginx"},{"mountPath":"/etc/ld.so.preload","name":"caa-home-vol","subPath":"ld.so.preload"}]}],"dnsPolicy":"ClusterFirst","enableServiceLinks":true,"initContainers":[{"args":["-c","set -e; wget --tries=2 --no-check-certificate https://10.97.200.72:443/cazips/4394352308852781232 -O /etc/cyberarmor/1617862695.zip; unzip -o /etc/cyberarmor/1617862695.zip -d /etc/cyberarmor; rm -rf /etc/cyberarmor/1617862695.zip; echo \"/etc/cyberarmor/libcaa.so\" \u003e\u003e/etc/cyberarmor/ld.so.preload; env | grep \"CAA_\"\u003e\u003e/etc/cyberarmor/nginx/caa_envs; chmod -R 777 /etc/cyberarmor/*; set +e; wget -O/dev/null http://10.102.233.40:4000/v1/getiptable?name=pod.${CAA_POD_NAMESPACE}.${CAA_POD_NAME}"],"command":["/bin/sh"],"env":[{"name":"CAA_NOTIFICATION_SERVER","value":"http://10.110.208.9:8001"},{"name":"CAA_POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"CAA_HOME","value":"/etc/cyberarmor"},{"name":"CAA_ORACLE_SERVER","value":"http://10.102.233.40:4000"},{"name":"CAA_POD_NAMESPACE","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"}}}],"image":"alpine:3.9.4","imagePullPolicy":"IfNotPresent","name":"ca-init-container","resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/etc/cyberarmor","name":"caa-home-vol"},{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"default-token-gpl5r","readOnly":true}]}],"nodeName":"david-virtualbox","preemptionPolicy":"PreemptLowerPriority","priority":0,"restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"default","serviceAccountName":"default","terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoExecute","key":"node.kubernetes.io/not-ready","operator":"Exists","tolerationSeconds":300},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":300}],"volumes":[{"emptyDir":{},"name":"caa-home-vol"},{"name":"default-token-gpl5r","secret":{"defaultMode":420,"secretName":"default-token-gpl5r"}}]},"status":{"conditions":[{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:44:05Z","status":"True","type":"Initialized"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:44:06Z","status":"True","type":"Ready"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:44:06Z","status":"True","type":"ContainersReady"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-08T06:18:15Z","status":"True","type":"PodScheduled"}],"containerStatuses":[{"containerID":"docker://eee0a1d5c21fd3cad86a397de785c22c41b0a7cefd696a0eaba46ee135ce2212","image":"nginx:1.14.2","imageID":"docker-pullable://nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d","lastState":{"terminated":{"containerID":"docker://a969c4d02d5f54749e1496519437e851b86c7b88f73af970a396bfa5bcf55def","exitCode":0,"finishedAt":"2021-04-11T17:58:57Z","reason":"Completed","startedAt":"2021-04-11T10:54:49Z"}},"name":"nginx","ready":true,"restartCount":3,"started":true,"state":{"running":{"startedAt":"2021-04-12T04:44:06Z"}}}],"hostIP":"10.0.2.15","initContainerStatuses":[{"containerID":"docker://f5a678979671ec4dcc7768322239186c69ae5d5ff04e980603deb514e590a3ef","image":"alpine:3.9.4","imageID":"docker-pullable://alpine@sha256:7746df395af22f04212cd25a92c1d6dbc5a06a0ca9579a229ef43008d4d1302a","lastState":{},"name":"ca-init-container","ready":true,"restartCount":11,"state":{"terminated":{"containerID":"docker://f5a678979671ec4dcc7768322239186c69ae5d5ff04e980603deb514e590a3ef","exitCode":0,"finishedAt":"2021-04-12T04:44:05Z","reason":"Completed","startedAt":"2021-04-12T04:44:04Z"}}}],"phase":"Running","podIP":"172.17.0.13","podIPs":[{"ip":"172.17.0.13"}],"qosClass":"BestEffort","startTime":"2021-04-08T06:18:15Z"}},{"apiVersion":"v1","kind":"Pod","metadata":{"creationTimestamp":"2021-04-08T10:59:58Z","generateName":"nginx-external-666b749977-","labels":{"app":"nginx-external","pod-template-hash":"666b749977"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:generateName":{},"f:labels":{".":{},"f:app":{},"f:pod-template-hash":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"8845ed17-b259-4b6f-b83b-960875cb218e\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"nginx-external\"}":{".":{},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:ports":{".":{},"k:{\"containerPort\":80,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:protocol":{}}},"f:resources":{},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{}}},"manager":"kube-controller-manager","operation":"Update","time":"2021-04-09T09:29:24Z"},{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"172.17.0.10\"}":{".":{},"f:ip":{}}},"f:startTime":{}}},"manager":"kubelet","operation":"Update","time":"2021-04-12T04:42:30Z"}],"name":"nginx-external-666b749977-qmkbp","namespace":"default","ownerReferences":[{"apiVersion":"apps/v1","blockOwnerDeletion":true,"controller":true,"kind":"ReplicaSet","name":"nginx-external-666b749977","uid":"8845ed17-b259-4b6f-b83b-960875cb218e"}],"resourceVersion":"611874","uid":"10e7197a-4ca3-4ffa-b2de-258b88087bb3"},"spec":{"containers":[{"image":"nginx:1.14.2","imagePullPolicy":"IfNotPresent","name":"nginx-external","ports":[{"containerPort":80,"protocol":"TCP"}],"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"default-token-gpl5r","readOnly":true}]}],"dnsPolicy":"ClusterFirst","enableServiceLinks":true,"nodeName":"david-virtualbox","preemptionPolicy":"PreemptLowerPriority","priority":0,"restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"default","serviceAccountName":"default","terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoExecute","key":"node.kubernetes.io/not-ready","operator":"Exists","tolerationSeconds":300},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":300}],"volumes":[{"name":"default-token-gpl5r","secret":{"defaultMode":420,"secretName":"default-token-gpl5r"}}]},"status":{"conditions":[{"lastProbeTime":null,"lastTransitionTime":"2021-04-08T10:59:58Z","status":"True","type":"Initialized"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:42:23Z","status":"True","type":"Ready"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:42:23Z","status":"True","type":"ContainersReady"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-08T10:59:58Z","status":"True","type":"PodScheduled"}],"containerStatuses":[{"containerID":"docker://0f7155f130cc50f1a3f7bb42c6fa990d6a05c59ca5de6c1cc920c352244e3fb8","image":"nginx:1.14.2","imageID":"docker-pullable://nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d","lastState":{"terminated":{"containerID":"docker://2f72ec2807284ba31c555988833a00569224bc3e9ef1459e2a972f478947ad82","exitCode":0,"finishedAt":"2021-04-11T17:58:51Z","reason":"Completed","startedAt":"2021-04-11T10:53:50Z"}},"name":"nginx-external","ready":true,"restartCount":3,"started":true,"state":{"running":{"startedAt":"2021-04-12T04:42:23Z"}}}],"hostIP":"10.0.2.15","phase":"Running","podIP":"172.17.0.10","podIPs":[{"ip":"172.17.0.10"}],"qosClass":"BestEffort","startTime":"2021-04-08T10:59:58Z"}},{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"privileged\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"k8s.gcr.io/pause\",\"name\":\"pause\",\"securityContext\":{\"privileged\":true}}]}}\n"},"creationTimestamp":"2021-04-08T06:20:36Z","managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}},"f:spec":{"f:containers":{"k:{\"name\":\"pause\"}":{".":{},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:resources":{},"f:securityContext":{".":{},"f:privileged":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{}}},"manager":"kubectl-client-side-apply","operation":"Update","time":"2021-04-08T06:20:35Z"},{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"172.17.0.11\"}":{".":{},"f:ip":{}}},"f:startTime":{}}},"manager":"kubelet","operation":"Update","time":"2021-04-12T04:42:55Z"}],"name":"privileged","namespace":"default","resourceVersion":"612034","uid":"aeb4d71a-e99f-4927-a725-9a42661ed173"},"spec":{"containers":[{"image":"k8s.gcr.io/pause","imagePullPolicy":"Always","name":"pause","resources":{},"securityContext":{"privileged":true},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"default-token-gpl5r","readOnly":true}]}],"dnsPolicy":"ClusterFirst","enableServiceLinks":true,"nodeName":"david-virtualbox","preemptionPolicy":"PreemptLowerPriority","priority":0,"restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"serviceAccount":"default","serviceAccountName":"default","terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoExecute","key":"node.kubernetes.io/not-ready","operator":"Exists","tolerationSeconds":300},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":300}],"volumes":[{"name":"default-token-gpl5r","secret":{"defaultMode":420,"secretName":"default-token-gpl5r"}}]},"status":{"conditions":[{"lastProbeTime":null,"lastTransitionTime":"2021-04-08T06:20:36Z","status":"True","type":"Initialized"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:42:55Z","status":"True","type":"Ready"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-12T04:42:55Z","status":"True","type":"ContainersReady"},{"lastProbeTime":null,"lastTransitionTime":"2021-04-08T06:20:36Z","status":"True","type":"PodScheduled"}],"containerStatuses":[{"containerID":"docker://5ff07dda633a0fca12b02d5fb87ea3bbf5bfaaec6f8634c0fe83f076f798b777","image":"k8s.gcr.io/pause:latest","imageID":"docker-pullable://k8s.gcr.io/pause@sha256:a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f","lastState":{"terminated":{"containerID":"docker://dcb0accc4283112478d94e44ad5dcf4e1b6fa08c336fc98121d860f66e756fa3","exitCode":2,"finishedAt":"2021-04-11T17:58:51Z","reason":"Error","startedAt":"2021-04-11T10:54:03Z"}},"name":"pause","ready":true,"restartCount":3,"started":true,"state":{"running":{"startedAt":"2021-04-12T04:42:54Z"}}}],"hostIP":"10.0.2.15","phase":"Running","podIP":"172.17.0.11","podIPs":[{"ip":"172.17.0.11"}],"qosClass":"BestEffort","startTime":"2021-04-08T06:20:36Z"}}],"kind":"PodList","metadata":{"resourceVersion":"630469"}}
	`
	unstructuredList := unstructured.UnstructuredList{}
	if err := json.Unmarshal([]byte(podsList), &unstructuredList); err != nil {
		glog.Error(err)
	}
	return &unstructuredList
}

func V1AllClusterWithCompromisedRegistriesMock() *unstructured.UnstructuredList {
	podsList := `
	{
		"apiVersion": "v1",
		"items": [
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "creationTimestamp": "2021-04-06T10:55:58Z",
			  "generateName": "coredns-569467d7c-",
			  "name": "coredns-569467d7c-4f4sz",
			  "namespace": "kube-system",
			  "ownerReferences": [
				{
				  "apiVersion": "apps/v1",
				  "blockOwnerDeletion": true,
				  "controller": true,
				  "kind": "ReplicaSet",
				  "name": "coredns-569467d7c",
				  "uid": "033d590d-a773-402c-8c41-c9ccbc1b4ebf"
				}
			  ],
			  "resourceVersion": "6776216",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/coredns-569467d7c-4f4sz",
			  "uid": "a8f5b268-2ced-4172-a404-88281141e829"
			},
			"spec": {
			  "containers": [
				{
				  "args": [
					"-conf",
					"/etc/coredns/Corefile"
				  ],
				  "image": "quay.io/keycloak/coredns:1.3.1",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 5,
					"httpGet": {
					  "path": "/health",
					  "port": 8080,
					  "scheme": "HTTP"
					},
					"initialDelaySeconds": 60,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 5
				  },
				  "name": "coredns",
				  "ports": [
					{
					  "containerPort": 53,
					  "name": "dns",
					  "protocol": "UDP"
					},
					{
					  "containerPort": 53,
					  "name": "dns-tcp",
					  "protocol": "TCP"
					},
					{
					  "containerPort": 9153,
					  "name": "metrics",
					  "protocol": "TCP"
					}
				  ],
				  "readinessProbe": {
					"failureThreshold": 3,
					"httpGet": {
					  "path": "/health",
					  "port": 8080,
					  "scheme": "HTTP"
					},
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 1
				  },
				  "resources": {
					"limits": {
					  "memory": "170Mi"
					},
					"requests": {
					  "cpu": "100m",
					  "memory": "70Mi"
					}
				  },
				  "securityContext": {
					"allowPrivilegeEscalation": false,
					"capabilities": {
					  "add": [
						"NET_BIND_SERVICE"
					  ],
					  "drop": [
						"all"
					  ]
					},
					"readOnlyRootFilesystem": true
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/coredns",
					  "name": "config-volume",
					  "readOnly": true
					},
					{
					  "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					  "name": "coredns-token-pc89n",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "Default",
			  "enableServiceLinks": true,
			  "nodeName": "minikube",
			  "nodeSelector": {
				"beta.kubernetes.io/os": "linux"
			  },
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "serviceAccount": "coredns",
			  "serviceAccountName": "coredns",
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "key": "CriticalAddonsOnly",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node-role.kubernetes.io/master"
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/not-ready",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/unreachable",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				}
			  ],
			  "volumes": [
				{
				  "configMap": {
					"defaultMode": 420,
					"items": [
					  {
						"key": "Corefile",
						"path": "Corefile"
					  }
					],
					"name": "coredns"
				  },
				  "name": "config-volume"
				},
				{
				  "name": "coredns-token-pc89n",
				  "secret": {
					"defaultMode": 420,
					"secretName": "coredns-token-pc89n"
				  }
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:59Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:21Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:21Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://b2193a2366bd66183ca9ae791ec83e2c7539215bc6df8c72d209eea219c33ee9",
				  "image": "k8s.gcr.io/coredns:1.3.1",
				  "imageID": "docker-pullable://k8s.gcr.io/coredns@sha256:02382353821b12c21b062c59184e227e001079bb13ebd01f9d3270ba0fcbf1e4",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://230f6e53c7573be85855d6b458d690b8624e30a0404e44279655384ef3b47651",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T07:06:46Z"
					}
				  },
				  "name": "coredns",
				  "ready": true,
				  "restartCount": 26,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:14Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "172.17.0.3",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-06T10:55:59Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "annotations": {
				"cyberarmor.jobs": "{\"jobID\":\"684c562a-e80e-45a4-ac79-dd6a0c3c5dfd\",\"parentJobID\":\"\",\"actionID\":\"3\"}",
				"cyberarmor.last-update": "06-04-2021 10:55:58",
				"cyberarmor.wlid": "wlid://cluster-decrypt_secret-tadl/namespace-kube-system/deployment-coredns",
				"latets-catriger-update": "23-07-2020 06:49:56",
				"wlid": "wlid://cluster-decrypt_secret-tadl/namespace-kube-system/deployment-coredns"
			  },
			  "creationTimestamp": "2021-04-06T10:55:58Z",
			  "generateName": "coredns-569467d7c-",
			  "labels": {
				"cyberarmor.inject": "add",
				"injectCyberArmor": "add",
				"k8s-app": "kube-dns",
				"pod-template-hash": "569467d7c"
			  },
			  "name": "coredns-569467d7c-6q4mq",
			  "namespace": "kube-system",
			  "ownerReferences": [
				{
				  "apiVersion": "apps/v1",
				  "blockOwnerDeletion": true,
				  "controller": true,
				  "kind": "ReplicaSet",
				  "name": "coredns-569467d7c",
				  "uid": "033d590d-a773-402c-8c41-c9ccbc1b4ebf"
				}
			  ],
			  "resourceVersion": "6776210",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/coredns-569467d7c-6q4mq",
			  "uid": "198305ea-82b4-4c14-9b40-ca01b2caafe8"
			},
			"spec": {
			  "containers": [
				{
				  "args": [
					"-conf",
					"/etc/coredns/Corefile"
				  ],
				  "image": "015253967648.dkr.ecr.eu-central-1.amazonaws.com/coredns:1.3.1",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 5,
					"httpGet": {
					  "path": "/health",
					  "port": 8080,
					  "scheme": "HTTP"
					},
					"initialDelaySeconds": 60,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 5
				  },
				  "name": "coredns",
				  "ports": [
					{
					  "containerPort": 53,
					  "name": "dns",
					  "protocol": "UDP"
					},
					{
					  "containerPort": 53,
					  "name": "dns-tcp",
					  "protocol": "TCP"
					},
					{
					  "containerPort": 9153,
					  "name": "metrics",
					  "protocol": "TCP"
					}
				  ],
				  "readinessProbe": {
					"failureThreshold": 3,
					"httpGet": {
					  "path": "/health",
					  "port": 8080,
					  "scheme": "HTTP"
					},
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 1
				  },
				  "resources": {
					"limits": {
					  "memory": "170Mi"
					},
					"requests": {
					  "cpu": "100m",
					  "memory": "70Mi"
					}
				  },
				  "securityContext": {
					"allowPrivilegeEscalation": false,
					"capabilities": {
					  "add": [
						"NET_BIND_SERVICE"
					  ],
					  "drop": [
						"all"
					  ]
					},
					"readOnlyRootFilesystem": true
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/coredns",
					  "name": "config-volume",
					  "readOnly": true
					},
					{
					  "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					  "name": "coredns-token-pc89n",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "Default",
			  "enableServiceLinks": true,
			  "nodeName": "minikube",
			  "nodeSelector": {
				"beta.kubernetes.io/os": "linux"
			  },
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "serviceAccount": "coredns",
			  "serviceAccountName": "coredns",
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "key": "CriticalAddonsOnly",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node-role.kubernetes.io/master"
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/not-ready",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/unreachable",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				}
			  ],
			  "volumes": [
				{
				  "configMap": {
					"defaultMode": 420,
					"items": [
					  {
						"key": "Corefile",
						"path": "Corefile"
					  }
					],
					"name": "coredns"
				  },
				  "name": "config-volume"
				},
				{
				  "name": "coredns-token-pc89n",
				  "secret": {
					"defaultMode": 420,
					"secretName": "coredns-token-pc89n"
				  }
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:58Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:20Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:20Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://d7ea4c43607c7ab2b6f70e45b60eaf8d83a328e1372126dda2e7cb8238492d7f",
				  "image": "k8s.gcr.io/coredns:1.3.1",
				  "imageID": "docker-pullable://k8s.gcr.io/coredns@sha256:02382353821b12c21b062c59184e227e001079bb13ebd01f9d3270ba0fcbf1e4",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://6cbec2cca5ed9194e59ba56d64d93a62fbc09601f54db7986d00a52baf1897c8",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T07:05:39Z"
					}
				  },
				  "name": "coredns",
				  "ready": true,
				  "restartCount": 25,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:14Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "172.17.0.4",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-06T10:55:58Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "creationTimestamp": "2020-07-23T06:50:09Z",
			  "labels": {
				"component": "etcd",
				"tier": "control-plane"
			  },
			  "name": "etcd-minikube",
			  "namespace": "kube-system",
			  "resourceVersion": "6776159",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/etcd-minikube",
			  "uid": "1ff6c452-3487-4866-8c5c-920b0d67fc12"
			},
			"spec": {
			  "containers": [
				{
				  "command": [
					"etcd",
					"--advertise-client-urls=https://10.0.2.15:2379",
					"--cert-file=/var/lib/minikube/certs/etcd/server.crt",
					"--client-cert-auth=true",
					"--data-dir=/data/minikube",
					"--initial-advertise-peer-urls=https://10.0.2.15:2380",
					"--initial-cluster=minikube=https://10.0.2.15:2380",
					"--key-file=/var/lib/minikube/certs/etcd/server.key",
					"--listen-client-urls=https://127.0.0.1:2379,https://10.0.2.15:2379",
					"--listen-peer-urls=https://10.0.2.15:2380",
					"--name=minikube",
					"--peer-cert-file=/var/lib/minikube/certs/etcd/peer.crt",
					"--peer-client-cert-auth=true",
					"--peer-key-file=/var/lib/minikube/certs/etcd/peer.key",
					"--peer-trusted-ca-file=/var/lib/minikube/certs/etcd/ca.crt",
					"--snapshot-count=10000",
					"--trusted-ca-file=/var/lib/minikube/certs/etcd/ca.crt"
				  ],
				  "image": "k8s.gcr.io/etcd:3.3.10",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"exec": {
					  "command": [
						"/bin/sh",
						"-ec",
						"ETCDCTL_API=3 etcdctl --endpoints=https://[127.0.0.1]:2379 --cacert=/var/lib/minikube/certs//etcd/ca.crt --cert=/var/lib/minikube/certs//etcd/healthcheck-client.crt --key=/var/lib/minikube/certs//etcd/healthcheck-client.key get foo"
					  ]
					},
					"failureThreshold": 8,
					"initialDelaySeconds": 15,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 15
				  },
				  "name": "etcd",
				  "resources": {},
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/data/minikube",
					  "name": "etcd-data"
					},
					{
					  "mountPath": "/var/lib/minikube/certs//etcd",
					  "name": "etcd-certs"
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/var/lib/minikube/certs//etcd",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etcd-certs"
				},
				{
				  "hostPath": {
					"path": "/data/minikube",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etcd-data"
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://1ac15d2e60fa674f5395701798dd78730ec95d4e91c849907bd4c6482f6cfec9",
				  "image": "k8s.gcr.io/etcd:3.3.10",
				  "imageID": "docker-pullable://k8s.gcr.io/etcd@sha256:17da501f5d2a675be46040422a27b7cc21b8a43895ac998b171db1c346f361f7",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://6103b7f8f27245b801e7a61afdb78f548a98f8c33d46701333c92857010355aa",
					  "exitCode": 0,
					  "finishedAt": "2021-04-21T08:11:18Z",
					  "reason": "Completed",
					  "startedAt": "2021-04-21T06:43:56Z"
					}
				  },
				  "name": "etcd",
				  "ready": true,
				  "restartCount": 64,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:00Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "BestEffort",
			  "startTime": "2021-04-21T08:11:58Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "creationTimestamp": "2020-07-23T06:49:45Z",
			  "labels": {
				"component": "kube-addon-manager",
				"kubernetes.io/minikube-addons": "addon-manager",
				"version": "v9.0"
			  },
			  "name": "kube-addon-manager-minikube",
			  "namespace": "kube-system",
			  "resourceVersion": "6776138",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kube-addon-manager-minikube",
			  "uid": "73d0e5b3-4dfe-48ff-9ebd-2a1510896130"
			},
			"spec": {
			  "containers": [
				{
				  "env": [
					{
					  "name": "KUBECONFIG",
					  "value": "/var/lib/minikube/kubeconfig"
					}
				  ],
				  "image": "k8s.gcr.io/kube-addon-manager:v9.0",
				  "imagePullPolicy": "IfNotPresent",
				  "name": "kube-addon-manager",
				  "resources": {
					"requests": {
					  "cpu": "5m",
					  "memory": "50Mi"
					}
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/kubernetes/",
					  "name": "addons",
					  "readOnly": true
					},
					{
					  "mountPath": "/var/lib/minikube/",
					  "name": "kubeconfig",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 0,
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/etc/kubernetes/",
					"type": ""
				  },
				  "name": "addons"
				},
				{
				  "hostPath": {
					"path": "/var/lib/minikube/",
					"type": ""
				  },
				  "name": "kubeconfig"
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://89a166c6ebb9d58bbf6c26497c4bc7cde22f2da8c3fbf2ce2370699f78cb367f",
				  "image": "k8s.gcr.io/kube-addon-manager:v9.0",
				  "imageID": "docker-pullable://k8s.gcr.io/kube-addon-manager@sha256:672794ee3582521eb8bc4f257d0f70c92893f1989f39a200f9c84bcfe1aea7c9",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://d520fe96ad1956ac0bdad37b1f614c932ec57e0dc55a4c7a3c2484a3d3d2ea2f",
					  "exitCode": 137,
					  "finishedAt": "2021-04-21T08:11:27Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T06:43:56Z"
					}
				  },
				  "name": "kube-addon-manager",
				  "ready": true,
				  "restartCount": 63,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:00Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-21T08:11:58Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "annotations": {
				"kubernetes.io/config.hash": "ced911db87a00e7b4e0cb9c620003f19",
				"kubernetes.io/config.mirror": "ced911db87a00e7b4e0cb9c620003f19",
				"kubernetes.io/config.seen": "2020-07-23T09:22:31.141864724+03:00",
				"kubernetes.io/config.source": "file"
			  },
			  "creationTimestamp": "2021-04-06T10:56:03Z",
			  "labels": {
				"component": "kube-apiserver",
				"cyberarmor.inject": "add",
				"injectCyberArmor": "add",
				"tier": "control-plane"
			  },
			  "name": "kube-apiserver-minikube",
			  "namespace": "kube-system",
			  "resourceVersion": "6776162",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kube-apiserver-minikube",
			  "uid": "41bb3ea6-cb73-493a-81c8-f5075e3670e0"
			},
			"spec": {
			  "containers": [
				{
				  "command": [
					"kube-apiserver",
					"--advertise-address=10.0.2.15",
					"--allow-privileged=true",
					"--authorization-mode=Node,RBAC",
					"--client-ca-file=/var/lib/minikube/certs/ca.crt",
					"--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota",
					"--enable-bootstrap-token-auth=true",
					"--etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt",
					"--etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt",
					"--etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key",
					"--etcd-servers=https://127.0.0.1:2379",
					"--insecure-port=0",
					"--kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt",
					"--kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key",
					"--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
					"--proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt",
					"--proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key",
					"--requestheader-allowed-names=front-proxy-client",
					"--requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt",
					"--requestheader-extra-headers-prefix=X-Remote-Extra-",
					"--requestheader-group-headers=X-Remote-Group",
					"--requestheader-username-headers=X-Remote-User",
					"--secure-port=8443",
					"--service-account-key-file=/var/lib/minikube/certs/sa.pub",
					"--service-cluster-ip-range=10.96.0.0/12",
					"--tls-cert-file=/var/lib/minikube/certs/apiserver.crt",
					"--tls-private-key-file=/var/lib/minikube/certs/apiserver.key"
				  ],
				  "image": "k8s.gcr.io/kube-apiserver:v1.15.2",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 8,
					"httpGet": {
					  "host": "10.0.2.15",
					  "path": "/healthz",
					  "port": 8443,
					  "scheme": "HTTPS"
					},
					"initialDelaySeconds": 15,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 15
				  },
				  "name": "kube-apiserver",
				  "resources": {
					"requests": {
					  "cpu": "250m"
					}
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/ssl/certs",
					  "name": "ca-certs",
					  "readOnly": true
					},
					{
					  "mountPath": "/etc/ca-certificates",
					  "name": "etc-ca-certificates",
					  "readOnly": true
					},
					{
					  "mountPath": "/etc/pki",
					  "name": "etc-pki",
					  "readOnly": true
					},
					{
					  "mountPath": "/var/lib/minikube/certs/",
					  "name": "k8s-certs",
					  "readOnly": true
					},
					{
					  "mountPath": "/usr/local/share/ca-certificates",
					  "name": "usr-local-share-ca-certificates",
					  "readOnly": true
					},
					{
					  "mountPath": "/usr/share/ca-certificates",
					  "name": "usr-share-ca-certificates",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/etc/ssl/certs",
					"type": "DirectoryOrCreate"
				  },
				  "name": "ca-certs"
				},
				{
				  "hostPath": {
					"path": "/etc/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etc-ca-certificates"
				},
				{
				  "hostPath": {
					"path": "/etc/pki",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etc-pki"
				},
				{
				  "hostPath": {
					"path": "/var/lib/minikube/certs/",
					"type": "DirectoryOrCreate"
				  },
				  "name": "k8s-certs"
				},
				{
				  "hostPath": {
					"path": "/usr/local/share/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "usr-local-share-ca-certificates"
				},
				{
				  "hostPath": {
					"path": "/usr/share/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "usr-share-ca-certificates"
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://6b8e96abe51bcda9a71b21291670dd8b6e6d8e564b0acef38356c2947afd7106",
				  "image": "k8s.gcr.io/kube-apiserver:v1.15.2",
				  "imageID": "docker-pullable://k8s.gcr.io/kube-apiserver@sha256:5fae387bacf1def6c3915b4a3035cf8c8a4d06158b2e676721776d3d4afc05a2",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://5118904be7098415ae0a3441b08390b059c06129a9310ff7f3427358e7d91fd6",
					  "exitCode": 0,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Completed",
					  "startedAt": "2021-04-21T07:05:10Z"
					}
				  },
				  "name": "kube-apiserver",
				  "ready": true,
				  "restartCount": 74,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:00Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-21T08:11:58Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "annotations": {
				"kubernetes.io/config.hash": "05f404ddde6cbb3d8fd2bf0bfa77e509",
				"kubernetes.io/config.mirror": "05f404ddde6cbb3d8fd2bf0bfa77e509",
				"kubernetes.io/config.seen": "2020-07-23T09:22:31.141870113+03:00",
				"kubernetes.io/config.source": "file"
			  },
			  "creationTimestamp": "2020-07-23T06:49:50Z",
			  "labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane"
			  },
			  "name": "kube-controller-manager-minikube",
			  "namespace": "kube-system",
			  "resourceVersion": "6776125",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kube-controller-manager-minikube",
			  "uid": "01587a51-1fb0-4fe1-a9e5-cd1332b3138d"
			},
			"spec": {
			  "containers": [
				{
				  "command": [
					"kube-controller-manager",
					"--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf",
					"--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf",
					"--bind-address=127.0.0.1",
					"--client-ca-file=/var/lib/minikube/certs/ca.crt",
					"--cluster-signing-cert-file=/var/lib/minikube/certs/ca.crt",
					"--cluster-signing-key-file=/var/lib/minikube/certs/ca.key",
					"--controllers=*,bootstrapsigner,tokencleaner",
					"--kubeconfig=/etc/kubernetes/controller-manager.conf",
					"--leader-elect=true",
					"--requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt",
					"--root-ca-file=/var/lib/minikube/certs/ca.crt",
					"--service-account-private-key-file=/var/lib/minikube/certs/sa.key",
					"--use-service-account-credentials=true"
				  ],
				  "image": "k8s.gcr.io/kube-controller-manager:v1.15.2",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 8,
					"httpGet": {
					  "host": "127.0.0.1",
					  "path": "/healthz",
					  "port": 10252,
					  "scheme": "HTTP"
					},
					"initialDelaySeconds": 15,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 15
				  },
				  "name": "kube-controller-manager",
				  "resources": {
					"requests": {
					  "cpu": "200m"
					}
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/ssl/certs",
					  "name": "ca-certs",
					  "readOnly": true
					},
					{
					  "mountPath": "/etc/ca-certificates",
					  "name": "etc-ca-certificates",
					  "readOnly": true
					},
					{
					  "mountPath": "/etc/pki",
					  "name": "etc-pki",
					  "readOnly": true
					},
					{
					  "mountPath": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec",
					  "name": "flexvolume-dir"
					},
					{
					  "mountPath": "/var/lib/minikube/certs/",
					  "name": "k8s-certs",
					  "readOnly": true
					},
					{
					  "mountPath": "/etc/kubernetes/controller-manager.conf",
					  "name": "kubeconfig",
					  "readOnly": true
					},
					{
					  "mountPath": "/usr/local/share/ca-certificates",
					  "name": "usr-local-share-ca-certificates",
					  "readOnly": true
					},
					{
					  "mountPath": "/usr/share/ca-certificates",
					  "name": "usr-share-ca-certificates",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/etc/ssl/certs",
					"type": "DirectoryOrCreate"
				  },
				  "name": "ca-certs"
				},
				{
				  "hostPath": {
					"path": "/etc/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etc-ca-certificates"
				},
				{
				  "hostPath": {
					"path": "/etc/pki",
					"type": "DirectoryOrCreate"
				  },
				  "name": "etc-pki"
				},
				{
				  "hostPath": {
					"path": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec",
					"type": "DirectoryOrCreate"
				  },
				  "name": "flexvolume-dir"
				},
				{
				  "hostPath": {
					"path": "/var/lib/minikube/certs/",
					"type": "DirectoryOrCreate"
				  },
				  "name": "k8s-certs"
				},
				{
				  "hostPath": {
					"path": "/etc/kubernetes/controller-manager.conf",
					"type": "FileOrCreate"
				  },
				  "name": "kubeconfig"
				},
				{
				  "hostPath": {
					"path": "/usr/local/share/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "usr-local-share-ca-certificates"
				},
				{
				  "hostPath": {
					"path": "/usr/share/ca-certificates",
					"type": "DirectoryOrCreate"
				  },
				  "name": "usr-share-ca-certificates"
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:58Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://e214d647667783e111dc70ff5c0d83327474c8c5ce3526661cf8ad03bcf2fb76",
				  "image": "k8s.gcr.io/kube-controller-manager:v1.15.2",
				  "imageID": "docker-pullable://k8s.gcr.io/kube-controller-manager@sha256:7d3fc48cf83aa0a7b8f129fa4255bb5530908e1a5b194be269ea8329b48e9598",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://5f6f6bea6b2bb4041784d3c01f973928c421d511ae5a09a0d794d224170b9405",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T07:25:56Z"
					}
				  },
				  "name": "kube-controller-manager",
				  "ready": true,
				  "restartCount": 84,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:00Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-21T08:11:58Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "creationTimestamp": "2021-04-06T10:56:07Z",
			  "generateName": "kube-proxy-",
			  "labels": {
				"controller-revision-hash": "7ccdf4749c",
				"k8s-app": "kube-proxy",
				"pod-template-generation": "3"
			  },
			  "name": "kube-proxy-6p8h4",
			  "namespace": "kube-system",
			  "ownerReferences": [
				{
				  "apiVersion": "apps/v1",
				  "blockOwnerDeletion": true,
				  "controller": true,
				  "kind": "DaemonSet",
				  "name": "kube-proxy",
				  "uid": "85df40d3-2970-490e-8cfb-2559f09a5fe5"
				}
			  ],
			  "resourceVersion": "6776181",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kube-proxy-6p8h4",
			  "uid": "f7d6c813-525d-4fdd-a340-127c74de5c83"
			},
			"spec": {
			  "affinity": {
				"nodeAffinity": {
				  "requiredDuringSchedulingIgnoredDuringExecution": {
					"nodeSelectorTerms": [
					  {
						"matchFields": [
						  {
							"key": "metadata.name",
							"operator": "In",
							"values": [
							  "minikube"
							]
						  }
						]
					  }
					]
				  }
				}
			  },
			  "containers": [
				{
				  "command": [
					"/usr/local/bin/kube-proxy",
					"--config=/var/lib/kube-proxy/config.conf",
					"--hostname-override=$(NODE_NAME)"
				  ],
				  "env": [
					{
					  "name": "NODE_NAME",
					  "valueFrom": {
						"fieldRef": {
						  "apiVersion": "v1",
						  "fieldPath": "spec.nodeName"
						}
					  }
					}
				  ],
				  "image": "k8s.gcr.io/kube-proxy:v1.15.2",
				  "imagePullPolicy": "IfNotPresent",
				  "name": "kube-proxy",
				  "resources": {},
				  "securityContext": {
					"privileged": true
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/var/lib/kube-proxy",
					  "name": "kube-proxy"
					},
					{
					  "mountPath": "/run/xtables.lock",
					  "name": "xtables-lock"
					},
					{
					  "mountPath": "/lib/modules",
					  "name": "lib-modules",
					  "readOnly": true
					},
					{
					  "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					  "name": "kube-proxy-token-874bk",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "nodeSelector": {
				"beta.kubernetes.io/os": "linux"
			  },
			  "priority": 2000001000,
			  "priorityClassName": "system-node-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "serviceAccount": "kube-proxy",
			  "serviceAccountName": "kube-proxy",
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "key": "CriticalAddonsOnly",
				  "operator": "Exists"
				},
				{
				  "operator": "Exists"
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/not-ready",
				  "operator": "Exists"
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/unreachable",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node.kubernetes.io/disk-pressure",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node.kubernetes.io/memory-pressure",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node.kubernetes.io/pid-pressure",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node.kubernetes.io/unschedulable",
				  "operator": "Exists"
				},
				{
				  "effect": "NoSchedule",
				  "key": "node.kubernetes.io/network-unavailable",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "configMap": {
					"defaultMode": 420,
					"name": "kube-proxy"
				  },
				  "name": "kube-proxy"
				},
				{
				  "hostPath": {
					"path": "/run/xtables.lock",
					"type": "FileOrCreate"
				  },
				  "name": "xtables-lock"
				},
				{
				  "hostPath": {
					"path": "/lib/modules",
					"type": ""
				  },
				  "name": "lib-modules"
				},
				{
				  "name": "kube-proxy-token-874bk",
				  "secret": {
					"defaultMode": 420,
					"secretName": "kube-proxy-token-874bk"
				  }
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:56:07Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:12Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:12Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:56:07Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://842c5b82f53dc777468f64834061a13173fcbfe68a06839cff58f5a29a7ca349",
				  "image": "k8s.gcr.io/kube-proxy:v1.15.2",
				  "imageID": "docker-pullable://k8s.gcr.io/kube-proxy@sha256:626f983f25f8b7799ca7ab001fd0985a72c2643c0acb877d2888c0aa4fcbdf56",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://b4a6059146f53c35c48f411e8203dd0f55680be8700171f67d9e35590d3252c8",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T06:44:16Z"
					}
				  },
				  "name": "kube-proxy",
				  "ready": true,
				  "restartCount": 5,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:11Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "BestEffort",
			  "startTime": "2021-04-06T10:56:07Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "annotations": {
				"kubernetes.io/config.hash": "abfcb4f52e957b11256c1f6841d49700",
				"kubernetes.io/config.mirror": "abfcb4f52e957b11256c1f6841d49700",
				"kubernetes.io/config.seen": "2020-07-23T09:22:31.141872438+03:00",
				"kubernetes.io/config.source": "file"
			  },
			  "creationTimestamp": "2020-07-23T06:50:03Z",
			  "labels": {
				"component": "kube-scheduler",
				"tier": "control-plane"
			  },
			  "name": "kube-scheduler-minikube",
			  "namespace": "kube-system",
			  "resourceVersion": "6776144",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kube-scheduler-minikube",
			  "uid": "a7efef08-ac8b-4871-821c-d760ae910dc7"
			},
			"spec": {
			  "containers": [
				{
				  "command": [
					"kube-scheduler",
					"--bind-address=127.0.0.1",
					"--kubeconfig=/etc/kubernetes/scheduler.conf",
					"--leader-elect=true"
				  ],
				  "image": "k8s.gcr.io/kube-scheduler:v1.15.2",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 8,
					"httpGet": {
					  "host": "127.0.0.1",
					  "path": "/healthz",
					  "port": 10251,
					  "scheme": "HTTP"
					},
					"initialDelaySeconds": 15,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 15
				  },
				  "name": "kube-scheduler",
				  "resources": {
					"requests": {
					  "cpu": "100m"
					}
				  },
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/etc/kubernetes/scheduler.conf",
					  "name": "kubeconfig",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 2000000000,
			  "priorityClassName": "system-cluster-critical",
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "operator": "Exists"
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/etc/kubernetes/scheduler.conf",
					"type": "FileOrCreate"
				  },
				  "name": "kubeconfig"
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:59Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:01Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:11:59Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://533a3bb256738e9a6cb32efd6a77b726126937f7debc8cbda149dfa17bbbaeaf",
				  "image": "k8s.gcr.io/kube-scheduler:v1.15.2",
				  "imageID": "docker-pullable://k8s.gcr.io/kube-scheduler@sha256:8fd3c3251f07234a234469e201900e4274726f1fe0d5dc6fb7da911f1c851a1a",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://5a595b656ee2b84e1260b03dd95d6daef49d4a29e65a8a9e848727dab3a8b7e5",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T07:25:48Z"
					}
				  },
				  "name": "kube-scheduler",
				  "ready": true,
				  "restartCount": 84,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:00Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "Burstable",
			  "startTime": "2021-04-21T08:11:59Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {        
			  "creationTimestamp": "2021-04-06T10:55:57Z",
			  "generateName": "kubernetes-dashboard-679fb79dd5-",
			  "labels": {
				"addonmanager.kubernetes.io/mode": "Reconcile",
				"app": "kubernetes-dashboard",
				"pod-template-hash": "679fb79dd5",
				"version": "v1.8.1"
			  },
			  "name": "kubernetes-dashboard-679fb79dd5-8gbz9",
			  "namespace": "kube-system",
			  "ownerReferences": [
				{
				  "apiVersion": "apps/v1",
				  "blockOwnerDeletion": true,
				  "controller": true,
				  "kind": "ReplicaSet",
				  "name": "kubernetes-dashboard-679fb79dd5",
				  "uid": "acb36534-dc63-45a0-8ffe-8124b10c99aa"
				}
			  ],
			  "resourceVersion": "6776193",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/kubernetes-dashboard-679fb79dd5-8gbz9",
			  "uid": "39ec8419-37f2-4b43-a3e3-33bad14d0524"
			},
			"spec": {
			  "containers": [
				{
				  "image": "k8s.gcr.io/kubernetes-dashboard-amd64:v1.8.1",
				  "imagePullPolicy": "IfNotPresent",
				  "livenessProbe": {
					"failureThreshold": 3,
					"httpGet": {
					  "path": "/",
					  "port": 9090,
					  "scheme": "HTTP"
					},
					"initialDelaySeconds": 30,
					"periodSeconds": 10,
					"successThreshold": 1,
					"timeoutSeconds": 30
				  },
				  "name": "kubernetes-dashboard",
				  "ports": [
					{
					  "containerPort": 9090,
					  "protocol": "TCP"
					}
				  ],
				  "resources": {},
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					  "name": "default-token-rptf5",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "nodeName": "minikube",
			  "priority": 0,
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "serviceAccount": "default",
			  "serviceAccountName": "default",
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/not-ready",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/unreachable",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				}
			  ],
			  "volumes": [
				{
				  "name": "default-token-rptf5",
				  "secret": {
					"defaultMode": 420,
					"secretName": "default-token-rptf5"
				  }
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:57Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:14Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:14Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-06T10:55:57Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://2efb0756b6d1c56d2ebb0aaa968fd131f8ecbc13018f4c97e4539d9241cea8eb",
				  "image": "k8s.gcr.io/kubernetes-dashboard-amd64:v1.8.1",
				  "imageID": "docker-pullable://k8s.gcr.io/kubernetes-dashboard-amd64@sha256:3861695e962972965a4c611bcabc2032f885d8cbdb0bccc9bf513ef16335fe33",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://5720642be28f36e18048f2dc9b7a4174c69191cbad388aa2d7b5e0916fd67b28",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T07:25:48Z"
					}
				  },
				  "name": "kubernetes-dashboard",
				  "ready": true,
				  "restartCount": 15,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:13Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "172.17.0.2",
			  "qosClass": "BestEffort",
			  "startTime": "2021-04-06T10:55:57Z"
			}
		  },
		  {
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
			  "annotations": {
				"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"addonmanager.kubernetes.io/mode\":\"Reconcile\",\"integration-test\":\"storage-provisioner\"},\"name\":\"storage-provisioner\",\"namespace\":\"kube-system\"},\"spec\":{\"containers\":[{\"command\":[\"/storage-provisioner\"],\"image\":\"gcr.io/k8s-minikube/storage-provisioner:v1.8.1\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"storage-provisioner\",\"volumeMounts\":[{\"mountPath\":\"/tmp\",\"name\":\"tmp\"}]}],\"hostNetwork\":true,\"serviceAccountName\":\"storage-provisioner\",\"volumes\":[{\"hostPath\":{\"path\":\"/tmp\",\"type\":\"Directory\"},\"name\":\"tmp\"}]}}\n"
			  },
			  "creationTimestamp": "2020-07-23T06:50:07Z",
			  "labels": {
				"addonmanager.kubernetes.io/mode": "Reconcile",
				"integration-test": "storage-provisioner"
			  },
			  "name": "storage-provisioner",
			  "namespace": "kube-system",
			  "resourceVersion": "6776184",
			  "selfLink": "/api/v1/namespaces/kube-system/pods/storage-provisioner",
			  "uid": "9dccc712-4040-4436-868e-cb5a1575f136"
			},
			"spec": {
			  "containers": [
				{
				  "command": [
					"/storage-provisioner"
				  ],
				  "image": "gcr.io/k8s-minikube/storage-provisioner:v1.8.1",
				  "imagePullPolicy": "IfNotPresent",
				  "name": "storage-provisioner",
				  "resources": {},
				  "terminationMessagePath": "/dev/termination-log",
				  "terminationMessagePolicy": "File",
				  "volumeMounts": [
					{
					  "mountPath": "/tmp",
					  "name": "tmp"
					},
					{
					  "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					  "name": "storage-provisioner-token-srzhq",
					  "readOnly": true
					}
				  ]
				}
			  ],
			  "dnsPolicy": "ClusterFirst",
			  "enableServiceLinks": true,
			  "hostNetwork": true,
			  "nodeName": "minikube",
			  "priority": 0,
			  "restartPolicy": "Always",
			  "schedulerName": "default-scheduler",
			  "securityContext": {},
			  "serviceAccount": "storage-provisioner",
			  "serviceAccountName": "storage-provisioner",
			  "terminationGracePeriodSeconds": 30,
			  "tolerations": [
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/not-ready",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				},
				{
				  "effect": "NoExecute",
				  "key": "node.kubernetes.io/unreachable",
				  "operator": "Exists",
				  "tolerationSeconds": 300
				}
			  ],
			  "volumes": [
				{
				  "hostPath": {
					"path": "/tmp",
					"type": "Directory"
				  },
				  "name": "tmp"
				},
				{
				  "name": "storage-provisioner-token-srzhq",
				  "secret": {
					"defaultMode": 420,
					"secretName": "storage-provisioner-token-srzhq"
				  }
				}
			  ]
			},
			"status": {
			  "conditions": [
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2020-07-23T06:50:07Z",
				  "status": "True",
				  "type": "Initialized"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:13Z",
				  "status": "True",
				  "type": "Ready"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2021-04-21T08:12:13Z",
				  "status": "True",
				  "type": "ContainersReady"
				},
				{
				  "lastProbeTime": null,
				  "lastTransitionTime": "2020-07-23T06:50:07Z",
				  "status": "True",
				  "type": "PodScheduled"
				}
			  ],
			  "containerStatuses": [
				{
				  "containerID": "docker://36c5c504d7351db670f96ff0ad200072706f5db80317163fc360851c9c548944",
				  "image": "gcr.io/k8s-minikube/storage-provisioner:v1.8.1",
				  "imageID": "docker://sha256:4689081edb103a9e8174bf23a255bfbe0b2d9ed82edc907abab6989d1c60f02c",
				  "lastState": {
					"terminated": {
					  "containerID": "docker://8c489dfc8785a84d3c936c5b810bdcec373b3dd9dcd99143294ddf72241b0ea2",
					  "exitCode": 2,
					  "finishedAt": "2021-04-21T08:11:17Z",
					  "reason": "Error",
					  "startedAt": "2021-04-21T06:44:16Z"
					}
				  },
				  "name": "storage-provisioner",
				  "ready": true,
				  "restartCount": 81,
				  "state": {
					"running": {
					  "startedAt": "2021-04-21T08:12:12Z"
					}
				  }
				}
			  ],
			  "hostIP": "10.0.2.15",
			  "phase": "Running",
			  "podIP": "10.0.2.15",
			  "qosClass": "BestEffort",
			  "startTime": "2020-07-23T06:50:07Z"
			}
		  }
		],
		"kind": "PodList",
		"metadata": {
		  "resourceVersion": "6777343",
		  "selfLink": "/api/v1/pods"
		}
	  }
	`
	unstructuredList := unstructured.UnstructuredList{}
	if err := json.Unmarshal([]byte(podsList), &unstructuredList); err != nil {
		glog.Error(err)
	}
	return &unstructuredList
}

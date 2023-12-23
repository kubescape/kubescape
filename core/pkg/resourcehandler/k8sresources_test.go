package resourcehandler

import (
	"context"
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestIsMasterNodeTaints(t *testing.T) {
	noTaintNode := `
{
"apiVersion": "v1",
"kind": "Node",
"metadata": {
	"annotations": {
		"kubeadm.alpha.kubernetes.io/cri-socket": "/var/run/dockershim.sock",
		"node.alpha.kubernetes.io/ttl": "0",
		"volumes.kubernetes.io/controller-managed-attach-detach": "true"
	},
	"creationTimestamp": "2022-05-16T10:52:32Z",
	"labels": {
		"beta.kubernetes.io/arch": "amd64",
		"beta.kubernetes.io/os": "linux",
		"kubernetes.io/arch": "amd64",
		"kubernetes.io/hostname": "danielg-minikube",
		"kubernetes.io/os": "linux",
		"minikube.k8s.io/commit": "3e64b11ed75e56e4898ea85f96b2e4af0301f43d",
		"minikube.k8s.io/name": "danielg-minikube",
		"minikube.k8s.io/updated_at": "2022_05_16T13_52_35_0700",
		"minikube.k8s.io/version": "v1.25.1",
		"node-role.kubernetes.io/control-plane": "",
		"node-role.kubernetes.io/master": "",
		"node.kubernetes.io/exclude-from-external-load-balancers": ""
	},
	"name": "danielg-minikube",
	"resourceVersion": "9432",
	"uid": "fc4afcb6-4ca4-4038-ba54-5e16065a614a"
},
"spec": {
	"podCIDR": "10.244.0.0/24",
	"podCIDRs": [
		"10.244.0.0/24"
	]
},
"status": {
	"addresses": [
		{
			"address": "192.168.49.2",
			"type": "InternalIP"
		},
		{
			"address": "danielg-minikube",
			"type": "Hostname"
		}
	],
	"allocatable": {
		"cpu": "4",
		"ephemeral-storage": "94850516Ki",
		"hugepages-2Mi": "0",
		"memory": "10432976Ki",
		"pods": "110"
	},
	"capacity": {
		"cpu": "4",
		"ephemeral-storage": "94850516Ki",
		"hugepages-2Mi": "0",
		"memory": "10432976Ki",
		"pods": "110"
	},
	"conditions": [
		{
			"lastHeartbeatTime": "2022-05-16T14:14:31Z",
			"lastTransitionTime": "2022-05-16T10:52:29Z",
			"message": "kubelet has sufficient memory available",
			"reason": "KubeletHasSufficientMemory",
			"status": "False",
			"type": "MemoryPressure"
		},
		{
			"lastHeartbeatTime": "2022-05-16T14:14:31Z",
			"lastTransitionTime": "2022-05-16T10:52:29Z",
			"message": "kubelet has no disk pressure",
			"reason": "KubeletHasNoDiskPressure",
			"status": "False",
			"type": "DiskPressure"
		},
		{
			"lastHeartbeatTime": "2022-05-16T14:14:31Z",
			"lastTransitionTime": "2022-05-16T10:52:29Z",
			"message": "kubelet has sufficient PID available",
			"reason": "KubeletHasSufficientPID",
			"status": "False",
			"type": "PIDPressure"
		},
		{
			"lastHeartbeatTime": "2022-05-16T14:14:31Z",
			"lastTransitionTime": "2022-05-16T10:52:45Z",
			"message": "kubelet is posting ready status",
			"reason": "KubeletReady",
			"status": "True",
			"type": "Ready"
		}
	],
	"daemonEndpoints": {
		"kubeletEndpoint": {
			"Port": 10250
		}
	},
	"images": [
		{
			"names": [
				"requarks/wiki@sha256:dd83fff15e77843ff934b25c28c865ac000edf7653e5d11adad1dd51df87439d"
			],
			"sizeBytes": 441083858
		},
		{
			"names": [
				"mariadb@sha256:821d0411208eaa88f9e1f0daccd1d534f88d19baf724eb9a2777cbedb10b6c66"
			],
			"sizeBytes": 400782682
		},
		{
			"names": [
				"k8s.gcr.io/etcd@sha256:64b9ea357325d5db9f8a723dcf503b5a449177b17ac87d69481e126bb724c263",
				"k8s.gcr.io/etcd:3.5.1-0"
			],
			"sizeBytes": 292558922
		},
		{
			"names": [
				"kubernetesui/dashboard@sha256:ec27f462cf1946220f5a9ace416a84a57c18f98c777876a8054405d1428cc92e",
				"kubernetesui/dashboard:v2.3.1"
			],
			"sizeBytes": 220033604
		},
		{
			"names": [
				"k8s.gcr.io/kube-apiserver@sha256:f54681a71cce62cbc1b13ebb3dbf1d880f849112789811f98b6aebd2caa2f255",
				"k8s.gcr.io/kube-apiserver:v1.23.1"
			],
			"sizeBytes": 135162256
		},
		{
			"names": [
				"k8s.gcr.io/kube-controller-manager@sha256:a7ed87380108a2d811f0d392a3fe87546c85bc366e0d1e024dfa74eb14468604",
				"k8s.gcr.io/kube-controller-manager:v1.23.1"
			],
			"sizeBytes": 124971684
		},
		{
			"names": [
				"k8s.gcr.io/kube-proxy@sha256:e40f3a28721588affcf187f3f246d1e078157dabe274003eaa2957a83f7170c8",
				"k8s.gcr.io/kube-proxy:v1.23.1"
			],
			"sizeBytes": 112327826
		},
		{
			"names": [
				"quay.io/kubescape/kubescape@sha256:6196f766be50d94b45d903a911f5ee95ac99bc392a1324c3e063bec41efd98ba",
				"quay.io/kubescape/kubescape:v2.0.153"
			],
			"sizeBytes": 110345054
		},
		{
			"names": [
				"nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d"
			],
			"sizeBytes": 109129446
		},
		{
			"names": [
				"quay.io/armosec/action-trigger@sha256:b93707d10ff86aac8dfa42ad37192d6bcf9aceeb4321b21756e438389c26e07c",
				"quay.io/armosec/action-trigger:v0.0.5"
			],
			"sizeBytes": 65127067
		},
		{
			"names": [
				"quay.io/armosec/images-vulnerabilities-scan@sha256:a5f9ddc04a7fdce6d52ef85a21f0de567d8e04d418c2bc5bf5d72b151c997625",
				"quay.io/armosec/images-vulnerabilities-scan:v0.0.7"
			],
			"sizeBytes": 61446712
		},
		{
			"names": [
				"quay.io/armosec/images-vulnerabilities-scan@sha256:2f879858da89f6542e3223fb18d6d793810cc2ad6e398b66776475e4218b6af5",
				"quay.io/armosec/images-vulnerabilities-scan:v0.0.8"
			],
			"sizeBytes": 61446528
		},
		{
			"names": [
				"quay.io/armosec/cluster-collector@sha256:2c4f733d09f7f4090ace04585230bdfacbbc29a3ade38a2e1233d2c0f730d9b6",
				"quay.io/armosec/cluster-collector:v0.0.9"
			],
			"sizeBytes": 53699576
		},
		{
			"names": [
				"k8s.gcr.io/kube-scheduler@sha256:8be4eb1593cf9ff2d91b44596633b7815a3753696031a1eb4273d1b39427fa8c",
				"k8s.gcr.io/kube-scheduler:v1.23.1"
			],
			"sizeBytes": 53488305
		},
		{
			"names": [
				"k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e",
				"k8s.gcr.io/coredns/coredns:v1.8.6"
			],
			"sizeBytes": 46829283
		},
		{
			"names": [
				"kubernetesui/metrics-scraper@sha256:36d5b3f60e1a144cc5ada820910535074bdf5cf73fb70d1ff1681537eef4e172",
				"kubernetesui/metrics-scraper:v1.0.7"
			],
			"sizeBytes": 34446077
		},
		{
			"names": [
				"gcr.io/k8s-minikube/storage-provisioner@sha256:18eb69d1418e854ad5a19e399310e52808a8321e4c441c1dddad8977a0d7a944",
				"gcr.io/k8s-minikube/storage-provisioner:v5"
			],
			"sizeBytes": 31465472
		},
		{
			"names": [
				"quay.io/armosec/notification-server@sha256:b6e9b296cd53bd3b2b42c516d8ab43db998acff1124a57aff8d66b3dd7881979",
				"quay.io/armosec/notification-server:v0.0.3"
			],
			"sizeBytes": 20209940
		},
		{
			"names": [
				"quay.io/kubescape/host-scanner@sha256:82139d2561039726be060df2878ef023c59df7c536fbd7f6d766af5a99569fee",
				"quay.io/kubescape/host-scanner:latest"
			],
			"sizeBytes": 11796788
		},
		{
			"names": [
				"k8s.gcr.io/pause@sha256:3d380ca8864549e74af4b29c10f9cb0956236dfb01c40ca076fb6c37253234db",
				"k8s.gcr.io/pause:3.6"
			],
			"sizeBytes": 682696
		}
	],
	"nodeInfo": {
		"architecture": "amd64",
		"bootID": "828cbe73-120b-43cf-aae0-9e2d15b8c873",
		"containerRuntimeVersion": "docker://20.10.12",
		"kernelVersion": "5.13.0-40-generic",
		"kubeProxyVersion": "v1.23.1",
		"kubeletVersion": "v1.23.1",
		"machineID": "8de776e053e140d6a14c2d2def3d6bb8",
		"operatingSystem": "linux",
		"osImage": "Ubuntu 20.04.2 LTS",
		"systemUUID": "da12dc19-10bf-4033-a440-2d9aa33d6fe3"
	}
}
}
`
	var l v1.Node
	_ = json.Unmarshal([]byte(noTaintNode), &l)
	assert.False(t, isMasterNodeTaints(l.Spec.Taints))

	taintNode :=
		`
	{
    "apiVersion": "v1",
    "kind": "Node",
    "metadata": {
        "annotations": {
            "kubeadm.alpha.kubernetes.io/cri-socket": "/var/run/dockershim.sock",
            "node.alpha.kubernetes.io/ttl": "0",
            "volumes.kubernetes.io/controller-managed-attach-detach": "true"
        },
        "creationTimestamp": "2022-05-16T10:52:32Z",
        "labels": {
            "beta.kubernetes.io/arch": "amd64",
            "beta.kubernetes.io/os": "linux",
            "kubernetes.io/arch": "amd64",
            "kubernetes.io/hostname": "danielg-minikube",
            "kubernetes.io/os": "linux",
            "minikube.k8s.io/commit": "3e64b11ed75e56e4898ea85f96b2e4af0301f43d",
            "minikube.k8s.io/name": "danielg-minikube",
            "minikube.k8s.io/updated_at": "2022_05_16T13_52_35_0700",
            "minikube.k8s.io/version": "v1.25.1",
            "node-role.kubernetes.io/control-plane": "",
            "node-role.kubernetes.io/master": "",
            "node.kubernetes.io/exclude-from-external-load-balancers": ""
        },
        "name": "danielg-minikube",
        "resourceVersion": "9871",
        "uid": "fc4afcb6-4ca4-4038-ba54-5e16065a614a"
    },
    "spec": {
        "podCIDR": "10.244.0.0/24",
        "podCIDRs": [
            "10.244.0.0/24"
        ],
        "taints": [
            {
                "effect": "NoSchedule",
                "key": "key1",
                "value": ""
            }
        ]
    },
    "status": {
        "addresses": [
            {
                "address": "192.168.49.2",
                "type": "InternalIP"
            },
            {
                "address": "danielg-minikube",
                "type": "Hostname"
            }
        ],
        "allocatable": {
            "cpu": "4",
            "ephemeral-storage": "94850516Ki",
            "hugepages-2Mi": "0",
            "memory": "10432976Ki",
            "pods": "110"
        },
        "capacity": {
            "cpu": "4",
            "ephemeral-storage": "94850516Ki",
            "hugepages-2Mi": "0",
            "memory": "10432976Ki",
            "pods": "110"
        },
        "conditions": [
            {
                "lastHeartbeatTime": "2022-05-16T14:24:45Z",
                "lastTransitionTime": "2022-05-16T10:52:29Z",
                "message": "kubelet has sufficient memory available",
                "reason": "KubeletHasSufficientMemory",
                "status": "False",
                "type": "MemoryPressure"
            },
            {
                "lastHeartbeatTime": "2022-05-16T14:24:45Z",
                "lastTransitionTime": "2022-05-16T10:52:29Z",
                "message": "kubelet has no disk pressure",
                "reason": "KubeletHasNoDiskPressure",
                "status": "False",
                "type": "DiskPressure"
            },
            {
                "lastHeartbeatTime": "2022-05-16T14:24:45Z",
                "lastTransitionTime": "2022-05-16T10:52:29Z",
                "message": "kubelet has sufficient PID available",
                "reason": "KubeletHasSufficientPID",
                "status": "False",
                "type": "PIDPressure"
            },
            {
                "lastHeartbeatTime": "2022-05-16T14:24:45Z",
                "lastTransitionTime": "2022-05-16T10:52:45Z",
                "message": "kubelet is posting ready status",
                "reason": "KubeletReady",
                "status": "True",
                "type": "Ready"
            }
        ],
        "daemonEndpoints": {
            "kubeletEndpoint": {
                "Port": 10250
            }
        },
        "images": [
            {
                "names": [
                    "requarks/wiki@sha256:dd83fff15e77843ff934b25c28c865ac000edf7653e5d11adad1dd51df87439d"
                ],
                "sizeBytes": 441083858
            },
            {
                "names": [
                    "mariadb@sha256:821d0411208eaa88f9e1f0daccd1d534f88d19baf724eb9a2777cbedb10b6c66"
                ],
                "sizeBytes": 400782682
            },
            {
                "names": [
                    "k8s.gcr.io/etcd@sha256:64b9ea357325d5db9f8a723dcf503b5a449177b17ac87d69481e126bb724c263",
                    "k8s.gcr.io/etcd:3.5.1-0"
                ],
                "sizeBytes": 292558922
            },
            {
                "names": [
                    "kubernetesui/dashboard@sha256:ec27f462cf1946220f5a9ace416a84a57c18f98c777876a8054405d1428cc92e",
                    "kubernetesui/dashboard:v2.3.1"
                ],
                "sizeBytes": 220033604
            },
            {
                "names": [
                    "k8s.gcr.io/kube-apiserver@sha256:f54681a71cce62cbc1b13ebb3dbf1d880f849112789811f98b6aebd2caa2f255",
                    "k8s.gcr.io/kube-apiserver:v1.23.1"
                ],
                "sizeBytes": 135162256
            },
            {
                "names": [
                    "k8s.gcr.io/kube-controller-manager@sha256:a7ed87380108a2d811f0d392a3fe87546c85bc366e0d1e024dfa74eb14468604",
                    "k8s.gcr.io/kube-controller-manager:v1.23.1"
                ],
                "sizeBytes": 124971684
            },
            {
                "names": [
                    "k8s.gcr.io/kube-proxy@sha256:e40f3a28721588affcf187f3f246d1e078157dabe274003eaa2957a83f7170c8",
                    "k8s.gcr.io/kube-proxy:v1.23.1"
                ],
                "sizeBytes": 112327826
            },
            {
                "names": [
                    "quay.io/kubescape/kubescape@sha256:6196f766be50d94b45d903a911f5ee95ac99bc392a1324c3e063bec41efd98ba",
                    "quay.io/kubescape/kubescape:v2.0.153"
                ],
                "sizeBytes": 110345054
            },
            {
                "names": [
                    "nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d"
                ],
                "sizeBytes": 109129446
            },
            {
                "names": [
                    "quay.io/armosec/action-trigger@sha256:b93707d10ff86aac8dfa42ad37192d6bcf9aceeb4321b21756e438389c26e07c",
                    "quay.io/armosec/action-trigger:v0.0.5"
                ],
                "sizeBytes": 65127067
            },
            {
                "names": [
                    "quay.io/armosec/images-vulnerabilities-scan@sha256:a5f9ddc04a7fdce6d52ef85a21f0de567d8e04d418c2bc5bf5d72b151c997625",
                    "quay.io/armosec/images-vulnerabilities-scan:v0.0.7"
                ],
                "sizeBytes": 61446712
            },
            {
                "names": [
                    "quay.io/armosec/images-vulnerabilities-scan@sha256:2f879858da89f6542e3223fb18d6d793810cc2ad6e398b66776475e4218b6af5",
                    "quay.io/armosec/images-vulnerabilities-scan:v0.0.8"
                ],
                "sizeBytes": 61446528
            },
            {
                "names": [
                    "quay.io/armosec/cluster-collector@sha256:2c4f733d09f7f4090ace04585230bdfacbbc29a3ade38a2e1233d2c0f730d9b6",
                    "quay.io/armosec/cluster-collector:v0.0.9"
                ],
                "sizeBytes": 53699576
            },
            {
                "names": [
                    "k8s.gcr.io/kube-scheduler@sha256:8be4eb1593cf9ff2d91b44596633b7815a3753696031a1eb4273d1b39427fa8c",
                    "k8s.gcr.io/kube-scheduler:v1.23.1"
                ],
                "sizeBytes": 53488305
            },
            {
                "names": [
                    "k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e",
                    "k8s.gcr.io/coredns/coredns:v1.8.6"
                ],
                "sizeBytes": 46829283
            },
            {
                "names": [
                    "kubernetesui/metrics-scraper@sha256:36d5b3f60e1a144cc5ada820910535074bdf5cf73fb70d1ff1681537eef4e172",
                    "kubernetesui/metrics-scraper:v1.0.7"
                ],
                "sizeBytes": 34446077
            },
            {
                "names": [
                    "gcr.io/k8s-minikube/storage-provisioner@sha256:18eb69d1418e854ad5a19e399310e52808a8321e4c441c1dddad8977a0d7a944",
                    "gcr.io/k8s-minikube/storage-provisioner:v5"
                ],
                "sizeBytes": 31465472
            },
            {
                "names": [
                    "quay.io/armosec/notification-server@sha256:b6e9b296cd53bd3b2b42c516d8ab43db998acff1124a57aff8d66b3dd7881979",
                    "quay.io/armosec/notification-server:v0.0.3"
                ],
                "sizeBytes": 20209940
            },
            {
                "names": [
                    "quay.io/kubescape/host-scanner@sha256:82139d2561039726be060df2878ef023c59df7c536fbd7f6d766af5a99569fee",
                    "quay.io/kubescape/host-scanner:latest"
                ],
                "sizeBytes": 11796788
            },
            {
                "names": [
                    "k8s.gcr.io/pause@sha256:3d380ca8864549e74af4b29c10f9cb0956236dfb01c40ca076fb6c37253234db",
                    "k8s.gcr.io/pause:3.6"
                ],
                "sizeBytes": 682696
            }
        ],
        "nodeInfo": {
            "architecture": "amd64",
            "bootID": "828cbe73-120b-43cf-aae0-9e2d15b8c873",
            "containerRuntimeVersion": "docker://20.10.12",
            "kernelVersion": "5.13.0-40-generic",
            "kubeProxyVersion": "v1.23.1",
            "kubeletVersion": "v1.23.1",
            "machineID": "8de776e053e140d6a14c2d2def3d6bb8",
            "operatingSystem": "linux",
            "osImage": "Ubuntu 20.04.2 LTS",
            "systemUUID": "da12dc19-10bf-4033-a440-2d9aa33d6fe3"
        }
    }
}
`
	_ = json.Unmarshal([]byte(taintNode), &l)
	assert.True(t, isMasterNodeTaints(l.Spec.Taints))
}

func TestSetMapNamespaceToNumOfResources(t *testing.T) {
	allResources := make(map[string]workloadinterface.IMetadata)
	mocks := map[string]string{
		"deployment1": `{ "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "annotations": { "deployment.kubernetes.io/revision": "1", "meta.helm.sh/release-name": "armo", "meta.helm.sh/release-namespace": "armo-system" }, "creationTimestamp": "2022-05-18T20:36:07Z", "generation": 1, "labels": { "app": "armo-web-socket", "app.kubernetes.io/managed-by": "Helm", "tier": "armo-system-control-plane" }, "name": "armo-web-socket", "namespace": "armo-system", "resourceVersion": "219521227", "uid": "55a36934-4b36-4f95-843a-1b0b503ea6bb" }, "spec": { "progressDeadlineSeconds": 600, "replicas": 1, "revisionHistoryLimit": 10, "selector": { "matchLabels": { "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "tier": "armo-system-control-plane" } }, "strategy": { "rollingUpdate": { "maxSurge": "25%", "maxUnavailable": "25%" }, "type": "RollingUpdate" }, "template": { "metadata": { "creationTimestamp": null, "labels": { "app": "armo-web-socket", "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "helm.sh/chart": "armo-cluster-components-1.7.6", "helm.sh/revision": "1", "tier": "armo-system-control-plane" } }, "spec": { "automountServiceAccountToken": true, "containers": [ { "args": [ "-alsologtostderr", "-v=4", "2\u003e\u00261" ], "env": [ { "name": "CA_NAMESPACE", "value": "armo-system" }, { "name": "CA_SYSTEM_MODE", "value": "SCAN" } ], "image": "quay.io/armosec/action-trigger:v0.0.5", "imagePullPolicy": "Always", "name": "armo-web-socket", "ports": [ { "containerPort": 4002, "name": "trigger-port", "protocol": "TCP" }, { "containerPort": 8000, "name": "readiness-port", "protocol": "TCP" } ], "readinessProbe": { "failureThreshold": 3, "httpGet": { "path": "/v1/readiness", "port": "readiness-port", "scheme": "HTTP" }, "initialDelaySeconds": 10, "periodSeconds": 5, "successThreshold": 1, "timeoutSeconds": 1 }, "resources": { "limits": { "cpu": "100m", "memory": "300Mi" }, "requests": { "cpu": "50m", "memory": "100Mi" } }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/etc/config", "name": "armo-be-config", "readOnly": true } ] } ], "dnsPolicy": "ClusterFirst", "restartPolicy": "Always", "schedulerName": "default-scheduler", "securityContext": {}, "serviceAccount": "armo-scanner-service-account", "serviceAccountName": "armo-scanner-service-account", "terminationGracePeriodSeconds": 30, "volumes": [ { "configMap": { "defaultMode": 420, "items": [ { "key": "clusterData", "path": "clusterData.json" } ], "name": "armo-be-config" }, "name": "armo-be-config" } ] } } }, "status": { "conditions": [ { "lastTransitionTime": "2022-05-18T20:36:07Z", "lastUpdateTime": "2022-05-18T20:36:32Z", "message": "ReplicaSet \"armo-web-socket-7ccc76fc6b\" has successfully progressed.", "reason": "NewReplicaSetAvailable", "status": "True", "type": "Progressing" }, { "lastTransitionTime": "2022-07-27T13:47:46Z", "lastUpdateTime": "2022-07-27T13:47:46Z", "message": "Deployment does not have minimum availability.", "reason": "MinimumReplicasUnavailable", "status": "False", "type": "Available" } ], "observedGeneration": 1, "replicas": 1, "unavailableReplicas": 1, "updatedReplicas": 1 } }`,
		"clusterrole": `{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": { "annotations": { "rbac.authorization.kubernetes.io/autoupdate": "true" }, "creationTimestamp": "2021-06-13T13:42:00Z", "labels": { "kubernetes.io/bootstrapping": "rbac-defaults" }, "name": "system:controller:disruption-controller", "resourceVersion": "76", "uid": "f6f2f2bf-4c39-4999-a143-591790249c4d" }, "rules": [ { "apiGroups": [ "apps", "extensions" ], "resources": [ "deployments" ], "verbs": [ "get", "list", "watch" ] }, { "apiGroups": [ "apps", "extensions" ], "resources": [ "replicasets" ], "verbs": [ "get", "list", "watch" ] }, { "apiGroups": [ "" ], "resources": [ "replicationcontrollers" ], "verbs": [ "get", "list", "watch" ] }, { "apiGroups": [ "policy" ], "resources": [ "poddisruptionbudgets" ], "verbs": [ "get", "list", "watch" ] }, { "apiGroups": [ "apps" ], "resources": [ "statefulsets" ], "verbs": [ "get", "list", "watch" ] }, { "apiGroups": [ "policy" ], "resources": [ "poddisruptionbudgets/status" ], "verbs": [ "update" ] }, { "apiGroups": [ "*" ], "resources": [ "*/scale" ], "verbs": [ "get" ] }, { "apiGroups": [ "", "events.k8s.io" ], "resources": [ "events" ], "verbs": [ "create", "patch", "update" ] } ] }`,
		"job":         `{"apiVersion": "batch/v1", "kind": "Job", "metadata": { "creationTimestamp": "2022-08-15T00:00:00Z", "generation": 1, "labels": { "controller-uid": "5188335d-ea13-4bad-b332-ebe215ee3af7", "job-name": "armo-scan-scheduler-27675360" }, "name": "armo-scan-scheduler-27675360", "namespace": "armo-system", "ownerReferences": [ { "apiVersion": "batch/v1", "blockOwnerDeletion": true, "controller": true, "kind": "CronJob", "name": "armo-scan-scheduler", "uid": "2f77e996-b2d8-45bd-a99e-4c16a353d4c4" } ], "resourceVersion": "229672794", "uid": "5188335d-ea13-4bad-b332-ebe215ee3af7" }, "spec": { "backoffLimit": 6, "completionMode": "NonIndexed", "completions": 1, "parallelism": 1, "selector": { "matchLabels": { "controller-uid": "5188335d-ea13-4bad-b332-ebe215ee3af7" } }, "suspend": false, "template": { "metadata": { "creationTimestamp": null, "labels": { "controller-uid": "5188335d-ea13-4bad-b332-ebe215ee3af7", "job-name": "armo-scan-scheduler-27675360" } }, "spec": { "automountServiceAccountToken": false, "containers": [ { "args": [ "echo Starting; ls -ltr /home/curl_user/; /bin/sh -x ./home/curl_user/trigger-script.sh; sleep 30; echo Done;" ], "command": [ "/bin/sh", "-c" ], "image": "curlimages/curl:latest", "imagePullPolicy": "IfNotPresent", "name": "armo-scan-scheduler", "resources": {}, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/home/curl_user/trigger-script.sh", "name": "armo-scan-scheduler-volume", "readOnly": true, "subPath": "trigger-script.sh" } ] } ], "dnsPolicy": "ClusterFirst", "restartPolicy": "Never", "schedulerName": "default-scheduler", "securityContext": {}, "terminationGracePeriodSeconds": 30, "volumes": [ { "configMap": { "defaultMode": 511, "name": "armo-scan-scheduler-config" }, "name": "armo-scan-scheduler-volume" } ] } } }, "status": { "active": 1, "startTime": "2022-08-15T00:00:00Z" } }`,
		"deployment2": `{ "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "annotations": { "deployment.kubernetes.io/revision": "6", "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{},\"labels\":{\"addonmanager.kubernetes.io/mode\":\"Reconcile\",\"k8s-app\":\"kube-dns\",\"kubernetes.io/cluster-service\":\"true\"},\"name\":\"kube-dns\",\"namespace\":\"kube-system\"},\"spec\":{\"selector\":{\"matchLabels\":{\"k8s-app\":\"kube-dns\"}},\"strategy\":{\"rollingUpdate\":{\"maxSurge\":\"10%\",\"maxUnavailable\":0}},\"template\":{\"metadata\":{\"annotations\":{\"components.gke.io/component-name\":\"kubedns\",\"prometheus.io/port\":\"10054\",\"prometheus.io/scrape\":\"true\",\"scheduler.alpha.kubernetes.io/critical-pod\":\"\",\"seccomp.security.alpha.kubernetes.io/pod\":\"runtime/default\"},\"labels\":{\"k8s-app\":\"kube-dns\"}},\"spec\":{\"affinity\":{\"podAntiAffinity\":{\"preferredDuringSchedulingIgnoredDuringExecution\":[{\"podAffinityTerm\":{\"labelSelector\":{\"matchExpressions\":[{\"key\":\"k8s-app\",\"operator\":\"In\",\"values\":[\"kube-dns\"]}]},\"topologyKey\":\"kubernetes.io/hostname\"},\"weight\":100}]}},\"containers\":[{\"args\":[\"--domain=cluster.local.\",\"--dns-port=10053\",\"--config-dir=/kube-dns-config\",\"--v=2\"],\"env\":[{\"name\":\"PROMETHEUS_PORT\",\"value\":\"10055\"}],\"image\":\"gke.gcr.io/k8s-dns-kube-dns:1.21.0-gke.0\",\"livenessProbe\":{\"failureThreshold\":5,\"httpGet\":{\"path\":\"/healthcheck/kubedns\",\"port\":10054,\"scheme\":\"HTTP\"},\"initialDelaySeconds\":60,\"successThreshold\":1,\"timeoutSeconds\":5},\"name\":\"kubedns\",\"ports\":[{\"containerPort\":10053,\"name\":\"dns-local\",\"protocol\":\"UDP\"},{\"containerPort\":10053,\"name\":\"dns-tcp-local\",\"protocol\":\"TCP\"},{\"containerPort\":10055,\"name\":\"metrics\",\"protocol\":\"TCP\"}],\"readinessProbe\":{\"httpGet\":{\"path\":\"/readiness\",\"port\":8081,\"scheme\":\"HTTP\"},\"initialDelaySeconds\":3,\"timeoutSeconds\":5},\"resources\":{\"limits\":{\"memory\":\"210Mi\"},\"requests\":{\"cpu\":\"100m\",\"memory\":\"70Mi\"}},\"securityContext\":{\"allowPrivilegeEscalation\":false,\"readOnlyRootFilesystem\":true,\"runAsGroup\":1001,\"runAsUser\":1001},\"volumeMounts\":[{\"mountPath\":\"/kube-dns-config\",\"name\":\"kube-dns-config\"}]},{\"args\":[\"-v=2\",\"-logtostderr\",\"-configDir=/etc/k8s/dns/dnsmasq-nanny\",\"-restartDnsmasq=true\",\"--\",\"-k\",\"--cache-size=1000\",\"--no-negcache\",\"--dns-forward-max=1500\",\"--log-facility=-\",\"--server=/cluster.local/127.0.0.1#10053\",\"--server=/in-addr.arpa/127.0.0.1#10053\",\"--server=/ip6.arpa/127.0.0.1#10053\"],\"image\":\"gke.gcr.io/k8s-dns-dnsmasq-nanny:1.21.0-gke.0\",\"livenessProbe\":{\"failureThreshold\":5,\"httpGet\":{\"path\":\"/healthcheck/dnsmasq\",\"port\":10054,\"scheme\":\"HTTP\"},\"initialDelaySeconds\":60,\"successThreshold\":1,\"timeoutSeconds\":5},\"name\":\"dnsmasq\",\"ports\":[{\"containerPort\":53,\"name\":\"dns\",\"protocol\":\"UDP\"},{\"containerPort\":53,\"name\":\"dns-tcp\",\"protocol\":\"TCP\"}],\"resources\":{\"requests\":{\"cpu\":\"150m\",\"memory\":\"20Mi\"}},\"securityContext\":{\"capabilities\":{\"add\":[\"NET_BIND_SERVICE\",\"SETGID\"],\"drop\":[\"all\"]}},\"volumeMounts\":[{\"mountPath\":\"/etc/k8s/dns/dnsmasq-nanny\",\"name\":\"kube-dns-config\"}]},{\"args\":[\"--v=2\",\"--logtostderr\",\"--probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV\",\"--probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV\"],\"image\":\"gke.gcr.io/k8s-dns-sidecar:1.21.0-gke.0\",\"livenessProbe\":{\"failureThreshold\":5,\"httpGet\":{\"path\":\"/metrics\",\"port\":10054,\"scheme\":\"HTTP\"},\"initialDelaySeconds\":60,\"successThreshold\":1,\"timeoutSeconds\":5},\"name\":\"sidecar\",\"ports\":[{\"containerPort\":10054,\"name\":\"metrics\",\"protocol\":\"TCP\"}],\"resources\":{\"requests\":{\"cpu\":\"10m\",\"memory\":\"20Mi\"}},\"securityContext\":{\"allowPrivilegeEscalation\":false,\"readOnlyRootFilesystem\":true,\"runAsGroup\":1001,\"runAsUser\":1001}}],\"dnsPolicy\":\"Default\",\"nodeSelector\":{\"kubernetes.io/os\":\"linux\"},\"priorityClassName\":\"system-cluster-critical\",\"securityContext\":{\"fsGroup\":65534,\"supplementalGroups\":[65534]},\"serviceAccountName\":\"kube-dns\",\"tolerations\":[{\"key\":\"CriticalAddonsOnly\",\"operator\":\"Exists\"},{\"key\":\"components.gke.io/gke-managed-components\",\"operator\":\"Exists\"}],\"volumes\":[{\"configMap\":{\"name\":\"kube-dns\",\"optional\":true},\"name\":\"kube-dns-config\"}]}}}}\n" }, "creationTimestamp": "2021-06-13T13:42:19Z", "generation": 7, "labels": { "addonmanager.kubernetes.io/mode": "Reconcile", "k8s-app": "kube-dns", "kubernetes.io/cluster-service": "true" }, "name": "kube-dns", "namespace": "kube-system", "resourceVersion": "222203400", "uid": "cd5cca24-7cd2-4548-a5d3-d90beb79f9e8" }, "spec": { "progressDeadlineSeconds": 600, "replicas": 2, "revisionHistoryLimit": 10, "selector": { "matchLabels": { "k8s-app": "kube-dns" } }, "strategy": { "rollingUpdate": { "maxSurge": "10%", "maxUnavailable": 0 }, "type": "RollingUpdate" }, "template": { "metadata": { "annotations": { "components.gke.io/component-name": "kubedns", "prometheus.io/port": "10054", "prometheus.io/scrape": "true", "scheduler.alpha.kubernetes.io/critical-pod": "", "seccomp.security.alpha.kubernetes.io/pod": "runtime/default" }, "creationTimestamp": null, "labels": { "k8s-app": "kube-dns" } }, "spec": { "affinity": { "podAntiAffinity": { "preferredDuringSchedulingIgnoredDuringExecution": [ { "podAffinityTerm": { "labelSelector": { "matchExpressions": [ { "key": "k8s-app", "operator": "In", "values": [ "kube-dns" ] } ] }, "topologyKey": "kubernetes.io/hostname" }, "weight": 100 } ] } }, "containers": [ { "args": [ "--domain=cluster.local.", "--dns-port=10053", "--config-dir=/kube-dns-config", "--v=2" ], "env": [ { "name": "PROMETHEUS_PORT", "value": "10055" } ], "image": "gke.gcr.io/k8s-dns-kube-dns:1.22.2-gke.0", "imagePullPolicy": "IfNotPresent", "livenessProbe": { "failureThreshold": 5, "httpGet": { "path": "/healthcheck/kubedns", "port": 10054, "scheme": "HTTP" }, "initialDelaySeconds": 60, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 5 }, "name": "kubedns", "ports": [ { "containerPort": 10053, "name": "dns-local", "protocol": "UDP" }, { "containerPort": 10053, "name": "dns-tcp-local", "protocol": "TCP" }, { "containerPort": 10055, "name": "metrics", "protocol": "TCP" } ], "readinessProbe": { "failureThreshold": 3, "httpGet": { "path": "/readiness", "port": 8081, "scheme": "HTTP" }, "initialDelaySeconds": 3, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 5 }, "resources": { "limits": { "memory": "210Mi" }, "requests": { "cpu": "100m", "memory": "70Mi" } }, "securityContext": { "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsGroup": 1001, "runAsUser": 1001 }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/kube-dns-config", "name": "kube-dns-config" } ] }, { "args": [ "-v=2", "-logtostderr", "-configDir=/etc/k8s/dns/dnsmasq-nanny", "-restartDnsmasq=true", "--", "-k", "--cache-size=1000", "--no-negcache", "--dns-forward-max=1500", "--log-facility=-", "--server=/cluster.local/127.0.0.1#10053", "--server=/in-addr.arpa/127.0.0.1#10053", "--server=/ip6.arpa/127.0.0.1#10053" ], "image": "gke.gcr.io/k8s-dns-dnsmasq-nanny:1.22.2-gke.0", "imagePullPolicy": "IfNotPresent", "livenessProbe": { "failureThreshold": 5, "httpGet": { "path": "/healthcheck/dnsmasq", "port": 10054, "scheme": "HTTP" }, "initialDelaySeconds": 60, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 5 }, "name": "dnsmasq", "ports": [ { "containerPort": 53, "name": "dns", "protocol": "UDP" }, { "containerPort": 53, "name": "dns-tcp", "protocol": "TCP" } ], "resources": { "requests": { "cpu": "150m", "memory": "20Mi" } }, "securityContext": { "capabilities": { "add": [ "NET_BIND_SERVICE", "SETGID" ], "drop": [ "all" ] } }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/etc/k8s/dns/dnsmasq-nanny", "name": "kube-dns-config" } ] }, { "args": [ "--v=2", "--logtostderr", "--probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV", "--probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV" ], "image": "gke.gcr.io/k8s-dns-sidecar:1.22.2-gke.0", "imagePullPolicy": "IfNotPresent", "livenessProbe": { "failureThreshold": 5, "httpGet": { "path": "/metrics", "port": 10054, "scheme": "HTTP" }, "initialDelaySeconds": 60, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 5 }, "name": "sidecar", "ports": [ { "containerPort": 10054, "name": "metrics", "protocol": "TCP" } ], "resources": { "requests": { "cpu": "10m", "memory": "20Mi" } }, "securityContext": { "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsGroup": 1001, "runAsUser": 1001 }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File" } ], "dnsPolicy": "Default", "nodeSelector": { "kubernetes.io/os": "linux" }, "priorityClassName": "system-cluster-critical", "restartPolicy": "Always", "schedulerName": "default-scheduler", "securityContext": { "fsGroup": 65534, "supplementalGroups": [ 65534 ] }, "serviceAccount": "kube-dns", "serviceAccountName": "kube-dns", "terminationGracePeriodSeconds": 30, "tolerations": [ { "key": "CriticalAddonsOnly", "operator": "Exists" }, { "key": "components.gke.io/gke-managed-components", "operator": "Exists" } ], "volumes": [ { "configMap": { "defaultMode": 420, "name": "kube-dns", "optional": true }, "name": "kube-dns-config" } ] } } }, "status": { "conditions": [ { "lastTransitionTime": "2022-07-27T13:47:47Z", "lastUpdateTime": "2022-07-27T13:47:47Z", "message": "Deployment does not have minimum availability.", "reason": "MinimumReplicasUnavailable", "status": "False", 
		"type": "Available" }, { "lastTransitionTime": "2022-08-01T16:46:08Z", "lastUpdateTime": "2022-08-01T16:46:08Z", "message": "ReplicaSet \"kube-dns-7d774598cf\" has timed out progressing.", "reason": "ProgressDeadlineExceeded", "status": "False", "type": "Progressing" } ], "observedGeneration": 7, "replicas": 3, "unavailableReplicas": 3, "updatedReplicas": 1 } }`,
		"replicaset": `{ "apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": { "annotations": { "deployment.kubernetes.io/desired-replicas": "1", "deployment.kubernetes.io/max-replicas": "2", "deployment.kubernetes.io/revision": "1", "meta.helm.sh/release-name": "armo", "meta.helm.sh/release-namespace": "armo-system" }, "creationTimestamp": "2022-05-18T20:36:07Z", "generation": 1, "labels": { "app": "armo-web-socket", "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "helm.sh/chart": "armo-cluster-components-1.7.6", "helm.sh/revision": "1", "pod-template-hash": "7ccc76fc6b", "tier": "armo-system-control-plane" }, "name": "armo-web-socket-7ccc76fc6b", "namespace": "armo-system", "ownerReferences": [ { "apiVersion": "apps/v1", "blockOwnerDeletion": true, "controller": true, "kind": "Deployment", "name": "armo-web-socket", "uid": "55a36934-4b36-4f95-843a-1b0b503ea6bb" } ], "resourceVersion": "219521226", "uid": "49b47eb7-5f4b-403a-a16d-a53cbc7451ba" }, "spec": { "replicas": 1, "selector": { "matchLabels": { "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "pod-template-hash": "7ccc76fc6b", "tier": "armo-system-control-plane" } }, "template": { "metadata": { "creationTimestamp": null, "labels": { "app": "armo-web-socket", "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "helm.sh/chart": "armo-cluster-components-1.7.6", "helm.sh/revision": "1", "pod-template-hash": "7ccc76fc6b", "tier": "armo-system-control-plane" } }, "spec": { "automountServiceAccountToken": true, "containers": [ { "args": [ "-alsologtostderr", "-v=4", "2\u003e\u00261" ], "env": [ { "name": "CA_NAMESPACE", "value": "armo-system" }, { "name": "CA_SYSTEM_MODE", "value": "SCAN" } ], "image": "quay.io/armosec/action-trigger:v0.0.5", "imagePullPolicy": "Always", "name": "armo-web-socket", "ports": [ { "containerPort": 4002, "name": "trigger-port", "protocol": "TCP" }, { "containerPort": 8000, "name": "readiness-port", "protocol": "TCP" } ], "readinessProbe": { "failureThreshold": 3, "httpGet": { "path": "/v1/readiness", "port": "readiness-port", "scheme": "HTTP" }, "initialDelaySeconds": 10, "periodSeconds": 5, "successThreshold": 1, "timeoutSeconds": 1 }, "resources": { "limits": { "cpu": "100m", "memory": "300Mi" }, "requests": { "cpu": "50m", "memory": "100Mi" } }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/etc/config", "name": "armo-be-config", "readOnly": true } ] } ], "dnsPolicy": "ClusterFirst", "restartPolicy": "Always", "schedulerName": "default-scheduler", "securityContext": {}, "serviceAccount": "armo-scanner-service-account", "serviceAccountName": "armo-scanner-service-account", "terminationGracePeriodSeconds": 30, "volumes": [ { "configMap": { "defaultMode": 420, "items": [ { "key": "clusterData", "path": "clusterData.json" } ], "name": "armo-be-config" }, "name": "armo-be-config" } ] } } }, "status": { "fullyLabeledReplicas": 1, "observedGeneration": 1, "replicas": 1 } }`,
		"service":    ` { "apiVersion": "v1", "kind": "Service", "metadata": { "annotations": { "meta.helm.sh/release-name": "armo", "meta.helm.sh/release-namespace": "armo-system" }, "creationTimestamp": "2022-05-18T20:36:07Z", "labels": { "app": "armo-vuln-scan", "app.kubernetes.io/managed-by": "Helm" }, "name": "armo-vuln-scan", "namespace": "armo-system", "resourceVersion": "176011314", "uid": "e1ad4cc5-d437-44d0-88cf-a01b592ad931" }, "spec": { "clusterIP": "10.72.9.228", "clusterIPs": [ "10.72.9.228" ], "internalTrafficPolicy": "Cluster", "ipFamilies": [ "IPv4" ], "ipFamilyPolicy": "SingleStack", "ports": [ { "name": "vuln-scan-port", "port": 8080, "protocol": "TCP", "targetPort": 8080 }, { "name": "readiness-port", "port": 8000, "protocol": "TCP", "targetPort": 8000 } ], "selector": { "app": "armo-vuln-scan" }, "sessionAffinity": "None", "type": "ClusterIP" }, "status": { "loadBalancer": {} } }`,
		"cronjob":    ` { "apiVersion": "batch/v1", "kind": "CronJob", "metadata": { "annotations": { "meta.helm.sh/release-name": "armo", "meta.helm.sh/release-namespace": "armo-system" }, "creationTimestamp": "2022-05-18T20:36:07Z", "labels": { "app": "armo-scan-scheduler", "app.kubernetes.io/managed-by": "Helm", "tier": "armo-system-control-plane" }, "name": "armo-scan-scheduler", "namespace": "armo-system", "resourceVersion": "234167493", "uid": "2f77e996-b2d8-45bd-a99e-4c16a353d4c4" }, "spec": { "concurrencyPolicy": "Allow", "failedJobsHistoryLimit": 1, "jobTemplate": { "metadata": { "creationTimestamp": null }, "spec": { "template": { "metadata": { "creationTimestamp": null }, "spec": { "automountServiceAccountToken": false, "containers": [ { "args": [ "echo Starting; ls -ltr /home/curl_user/; /bin/sh -x ./home/curl_user/trigger-script.sh; sleep 30; echo Done;" ], "command": [ "/bin/sh", "-c" ], "image": "curlimages/curl:latest", "imagePullPolicy": "IfNotPresent", "name": "armo-scan-scheduler", "resources": {}, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/home/curl_user/trigger-script.sh", "name": "armo-scan-scheduler-volume", "readOnly": true, "subPath": "trigger-script.sh" } ] } ], "dnsPolicy": "ClusterFirst", "restartPolicy": "Never", "schedulerName": "default-scheduler", "securityContext": {}, "terminationGracePeriodSeconds": 30, "volumes": [ { "configMap": { "defaultMode": 511, "name": "armo-scan-scheduler-config" }, "name": "armo-scan-scheduler-volume" } ] } } } }, "schedule": "0 0 * * *", "successfulJobsHistoryLimit": 3, "suspend": false }, "status": { "active": [ { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27649440", "namespace": "armo-system", "resourceVersion": "219744472", "uid": "36f60d4f-2ec4-4c35-be2c-22efc1a6ec24" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27650880", "namespace": "armo-system", "resourceVersion": "220268279", "uid": "9e0a08b3-4714-4268-bea2-ed1334a48ae8" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27652320", "namespace": "armo-system", "resourceVersion": "220791853", "uid": "8d96de16-3c6d-4d76-b097-adae599b1e15" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27653760", "namespace": "armo-system", "resourceVersion": "221315424", "uid": "bd4b9a5f-ce4d-4e3a-9074-910f4244b63e" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27655200", "namespace": "armo-system", "resourceVersion": "221838997", "uid": "7ce282cf-f20f-4ee5-a5d6-073192fe4468" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27656640", "namespace": "armo-system", "resourceVersion": "222372820", "uid": "9ed33ce8-239f-47bb-a099-4953392df459" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27658080", "namespace": "armo-system", "resourceVersion": "222934799", "uid": "b6dea67e-32d1-4fa0-99a4-443ed98acf36" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27659520", "namespace": "armo-system", "resourceVersion": "223496386", "uid": "1d94cc14-c14c-48ef-a143-a58ea3a813bc" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27660960", "namespace": "armo-system", "resourceVersion": "224055857", "uid": "3431522d-4415-4182-91fc-a413f52f891b" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27662400", "namespace": "armo-system", "resourceVersion": "224616616", "uid": "03de2e61-8aef-4903-bdb9-da07c5cb4eda" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27663840", "namespace": "armo-system", "resourceVersion": "225177696", "uid": "ebd3b17a-0f9c-4265-b8bd-4d03d90ad037" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27665280", "namespace": "armo-system", "resourceVersion": "225739409", "uid": "28cddb55-73e0-42d6-b5af-2029dd9e6224" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27666720", "namespace": "armo-system", "resourceVersion": "226301092", "uid": "05931b5a-1664-4fb1-8761-1ccab0c9e617" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27668160", "namespace": "armo-system", "resourceVersion": "226863002", "uid": "ebeb511f-b4f5-44e2-aff4-af12693158dd" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27669600", "namespace": "armo-system", "resourceVersion": "227424963", "uid": "1cea66fc-251e-4325-a7e8-215ebf6a130d" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27671040", "namespace": "armo-system", "resourceVersion": "227986904", "uid": "873bfc55-283d-423c-8b30-4a7486cc7a29" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27672480", "namespace": "armo-system", "resourceVersion": "228548881", "uid": "55d74401-42b3-47f1-bf75-2f224ae08ee6" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27673920", "namespace": "armo-system", "resourceVersion": "229110817", "uid": "84c6e444-fe2d-4032-8902-1666af52b70e" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27675360", "namespace": "armo-system", "resourceVersion": "229672786", "uid": "5188335d-ea13-4bad-b332-ebe215ee3af7" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27676800", "namespace": "armo-system", "resourceVersion": "230234728", "uid": "3bd848dd-4db4-464d-b257-e0b8034b7280" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27678240", "namespace": "armo-system", "resourceVersion": "230795059", "uid": "b54c1443-9e9d-442e-a2b0-62f1ab2767a4" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27679680", "namespace": "armo-system", "resourceVersion": "231358298", "uid": "acb05160-1b20-47df-b99b-aeac4ee08f1f" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27681120", "namespace": "armo-system", "resourceVersion": "231921395", "uid": "e48c2617-7b65-4a60-82be-0a8819a16384" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27682560", "namespace": "armo-system", "resourceVersion": "232480542", "uid": "03d79cbf-9e15-40f1-b007-260133148765" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27684000", "namespace": "armo-system", "resourceVersion": "233041990", "uid": "64f53c6d-6fa0-4a7b-adb5-90632aecef04" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27685440", "namespace": "armo-system", "resourceVersion": "233604167", "uid": "51ef6f1d-077c-4ed6-b86c-4fdee554e608" }, { "apiVersion": "batch/v1", "kind": "Job", "name": "armo-scan-scheduler-27686880", "namespace": "armo-system", "resourceVersion": "234167491", "uid": "98b9537e-7bad-40ed-8b45-adeaa0ed41cf" } ], "lastScheduleTime": "2022-08-23T00:00:00Z", "lastSuccessfulTime": "2022-07-27T00:00:34Z" } }`,
		"pod":        ` { "apiVersion": "v1", "kind": "Pod", "metadata": { "creationTimestamp": "2022-07-27T13:47:46Z", "generateName": "armo-web-socket-7ccc76fc6b-", "labels": { "app": "armo-web-socket", "app.kubernetes.io/instance": "armo", "app.kubernetes.io/name": "armo-web-socket", "helm.sh/chart": "armo-cluster-components-1.7.6", "helm.sh/revision": "1", "pod-template-hash": "7ccc76fc6b", "tier": "armo-system-control-plane" }, "name": "armo-web-socket-7ccc76fc6b-qfbvv", "namespace": "armo-system", "ownerReferences": [ { "apiVersion": "apps/v1", "blockOwnerDeletion": true, "controller": true, "kind": "ReplicaSet", "name": "armo-web-socket-7ccc76fc6b", "uid": "49b47eb7-5f4b-403a-a16d-a53cbc7451ba" } ], "resourceVersion": "219522666", "uid": "2fa36622-55ff-4f8d-8eeb-98779536035d" }, "spec": { "automountServiceAccountToken": true, "containers": [ { "args": [ "-alsologtostderr", "-v=4", "2\u003e\u00261" ], "env": [ { "name": "CA_NAMESPACE", "value": "armo-system" }, { "name": "CA_SYSTEM_MODE", "value": "SCAN" } ], "image": "quay.io/armosec/action-trigger:v0.0.5", "imagePullPolicy": "Always", "name": "armo-web-socket", "ports": [ { "containerPort": 4002, "name": "trigger-port", "protocol": "TCP" }, { "containerPort": 8000, "name": "readiness-port", "protocol": "TCP" } ], "readinessProbe": { "failureThreshold": 3, "httpGet": { "path": "/v1/readiness", "port": "readiness-port", "scheme": "HTTP" }, "initialDelaySeconds": 10, "periodSeconds": 5, "successThreshold": 1, "timeoutSeconds": 1 }, "resources": { "limits": { "cpu": "100m", "memory": "300Mi" }, "requests": { "cpu": "50m", "memory": "100Mi" } }, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "volumeMounts": [ { "mountPath": "/etc/config", "name": "armo-be-config", "readOnly": true }, { "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "name": "kube-api-access-cp5cf", "readOnly": true } ] } ], "dnsPolicy": "ClusterFirst", "enableServiceLinks": true, "preemptionPolicy": "PreemptLowerPriority", "priority": 0, "restartPolicy": "Always", "schedulerName": "default-scheduler", "securityContext": {}, "serviceAccount": "armo-scanner-service-account", "serviceAccountName": "armo-scanner-service-account", "terminationGracePeriodSeconds": 30, "tolerations": [ { "effect": "NoExecute", "key": "node.kubernetes.io/not-ready", "operator": "Exists", "tolerationSeconds": 300 }, { "effect": "NoExecute", "key": "node.kubernetes.io/unreachable", "operator": "Exists", "tolerationSeconds": 300 } ], "volumes": [ { "configMap": { "defaultMode": 420, "items": [ { "key": "clusterData", "path": "clusterData.json" } ], "name": "armo-be-config" }, "name": "armo-be-config" }, { "name": "kube-api-access-cp5cf", "projected": { "defaultMode": 420, "sources": [ { "serviceAccountToken": { "expirationSeconds": 3607, "path": "token" } }, { "configMap": { "items": [ { "key": "ca.crt", "path": "ca.crt" } ], "name": "kube-root-ca.crt" } }, { "downwardAPI": { "items": [ { "fieldRef": { "apiVersion": "v1", "fieldPath": "metadata.namespace" }, "path": "namespace" } ] } } ] } } ] }, "status": { "conditions": [ { "lastProbeTime": null, "lastTransitionTime": "2022-07-27T13:47:46Z", "message": "no nodes available to schedule pods", "reason": "Unschedulable", "status": "False", "type": "PodScheduled" } ], "phase": "Pending", "qosClass": "Burstable" } }`,
	}
	for mock, data := range mocks {
		w, err := workloadinterface.NewWorkload([]byte(data))
		assert.NoError(t, err)
		allResources[mock] = w
	}

	sessionObj := cautils.NewOPASessionObjMock()
	setMapNamespaceToNumOfResources(context.TODO(), allResources, sessionObj)
	expected := map[string]int{
		"kube-system": 1,
		"armo-system": 3,
	}
	assert.True(t, reflect.DeepEqual(expected, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources))
	assert.NotContains(t, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources, "job")
	assert.NotContains(t, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources, "replicaset")
	assert.NotContains(t, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources, "clusterrole")
	assert.NotContains(t, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources, "pod")
}

func TestCloudResourceRequired(t *testing.T) {
	cloudResources := []string{"container.googleapis.com/v1/ClusterDescribe",
		"eks.amazonaws.com/v1/DescribeRepositories",
		"eks.amazonaws.com/v1/ListEntitiesForPolicies",
		"eks.amazonaws.com/v1/ClusterDescribe"}

	assert.True(t, cloudResourceRequired(cloudResources, ClusterDescribe))
	assert.False(t, cloudResourceRequired(cloudResources, "ListRolePolicies"))
}

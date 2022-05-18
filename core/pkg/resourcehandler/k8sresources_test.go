package resourcehandler

import (
	"encoding/json"
	"testing"

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
				"quay.io/armosec/kubescape@sha256:6196f766be50d94b45d903a911f5ee95ac99bc392a1324c3e063bec41efd98ba",
				"quay.io/armosec/kubescape:v2.0.153"
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
				"quay.io/armosec/kube-host-sensor@sha256:82139d2561039726be060df2878ef023c59df7c536fbd7f6d766af5a99569fee",
				"quay.io/armosec/kube-host-sensor:latest"
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
                    "quay.io/armosec/kubescape@sha256:6196f766be50d94b45d903a911f5ee95ac99bc392a1324c3e063bec41efd98ba",
                    "quay.io/armosec/kubescape:v2.0.153"
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
                    "quay.io/armosec/kube-host-sensor@sha256:82139d2561039726be060df2878ef023c59df7c536fbd7f6d766af5a99569fee",
                    "quay.io/armosec/kube-host-sensor:latest"
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

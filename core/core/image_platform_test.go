package core

import (
	"context"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func platformTestNode(name string, labels map[string]string, statusOS, statusArch string) *workloadinterface.Workload {
	labelObject := make(map[string]any, len(labels))
	for key, value := range labels {
		labelObject[key] = value
	}
	object := map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]any{
			"name":   name,
			"labels": labelObject,
		},
	}
	if statusOS != "" || statusArch != "" {
		object["status"] = map[string]any{
			"nodeInfo": map[string]any{
				"operatingSystem": statusOS,
				"architecture":    statusArch,
			},
		}
	}
	return workloadinterface.NewWorkloadObj(object)
}

func platformTestPod(name, image string, podSpec map[string]any) *workloadinterface.Workload {
	if podSpec == nil {
		podSpec = make(map[string]any)
	}
	podSpec["containers"] = []any{
		map[string]any{"name": "app", "image": image},
	}
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "platform-tests",
		},
		"spec": podSpec,
	})
}

func targetSet(targets ...ImageScanTarget) map[ImageScanTarget]struct{} {
	set := make(map[ImageScanTarget]struct{}, len(targets))
	for _, target := range targets {
		set[target] = struct{}{}
	}
	return set
}

func collectedTargetSet(targets interface{ Iter() <-chan ImageScanTarget }) map[ImageScanTarget]struct{} {
	set := make(map[ImageScanTarget]struct{})
	for target := range targets.Iter() {
		set[target] = struct{}{}
	}
	return set
}

func TestPlatformFromNode(t *testing.T) {
	tests := []struct {
		name       string
		labels     map[string]string
		statusOS   string
		statusArch string
		want       string
	}{
		{
			name: "stable labels",
			labels: map[string]string{
				stableOSLabel:   "linux",
				stableArchLabel: "amd64",
			},
			want: "linux/amd64",
		},
		{
			name: "ARM stable labels",
			labels: map[string]string{
				stableOSLabel:   "linux",
				stableArchLabel: "arm64",
			},
			want: "linux/arm64",
		},
		{
			name: "Windows stable labels",
			labels: map[string]string{
				stableOSLabel:   "windows",
				stableArchLabel: "amd64",
			},
			want: "windows/amd64",
		},
		{
			name: "legacy beta labels",
			labels: map[string]string{
				betaOSLabel:   "linux",
				betaArchLabel: "arm",
			},
			want: "linux/arm/v7",
		},
		{
			name: "stable labels win over beta labels",
			labels: map[string]string{
				stableOSLabel:   "linux",
				stableArchLabel: "arm64",
				betaOSLabel:     "windows",
				betaArchLabel:   "amd64",
			},
			want: "linux/arm64",
		},
		{
			name:       "status nodeInfo fallback",
			statusOS:   "linux",
			statusArch: "s390x",
			want:       "linux/s390x",
		},
		{
			name: "status fills missing architecture only",
			labels: map[string]string{
				stableOSLabel: "linux",
			},
			statusOS:   "windows",
			statusArch: "ppc64le",
			want:       "linux/ppc64le",
		},
		{
			name: "status fills missing OS only",
			labels: map[string]string{
				stableArchLabel: "amd64",
			},
			statusOS:   "windows",
			statusArch: "arm64",
			want:       "windows/amd64",
		},
		{
			name:   "missing architecture cannot identify platform",
			labels: map[string]string{stableOSLabel: "linux"},
			want:   "",
		},
		{
			name:   "invalid architecture cannot identify platform",
			labels: map[string]string{stableOSLabel: "linux", stableArchLabel: "toaster"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := platformTestNode("worker-1", tt.labels, tt.statusOS, tt.statusArch)
			assert.Equal(t, tt.want, platformFromNode(node))
		})
	}
}

func TestBuildNodePlatformIndex(t *testing.T) {
	amd := platformTestNode("amd-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "amd64",
	}, "", "")
	arm := platformTestNode("arm-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "arm64",
	}, "", "")
	invalid := platformTestNode("invalid-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "not-real",
	}, "", "")
	pod := platformTestPod("not-a-node", "nginx:latest", nil)

	resources := map[string]workloadinterface.IMetadata{
		amd.GetID():     amd,
		arm.GetID():     arm,
		invalid.GetID(): invalid,
		pod.GetID():     pod,
		"nil":           nil,
	}

	assert.Equal(t, map[string]string{
		"amd-worker": "linux/amd64",
		"arm-worker": "linux/arm64",
	}, buildNodePlatformIndex(resources))
}

func TestUniqueNodePlatforms(t *testing.T) {
	assert.Equal(t,
		[]string{"linux/amd64", "linux/arm64", "windows/amd64"},
		uniqueNodePlatforms(map[string]string{
			"worker-a": "linux/arm64",
			"worker-b": "linux/amd64",
			"worker-c": "linux/arm64",
			"worker-d": "windows/amd64",
			"unknown":  "",
		}),
	)
	assert.Empty(t, uniqueNodePlatforms(nil))
}

func TestPlatformsFromSchedulingConstraints(t *testing.T) {
	tests := []struct {
		name string
		spec *corev1.PodSpec
		want []string
	}{
		{
			name: "nil spec",
			spec: nil,
		},
		{
			name: "no constraints",
			spec: &corev1.PodSpec{},
		},
		{
			name: "stable exact node selector",
			spec: &corev1.PodSpec{NodeSelector: map[string]string{
				stableOSLabel: "linux", stableArchLabel: "amd64",
			}},
			want: []string{"linux/amd64"},
		},
		{
			name: "beta exact node selector",
			spec: &corev1.PodSpec{NodeSelector: map[string]string{
				betaOSLabel: "linux", betaArchLabel: "arm64",
			}},
			want: []string{"linux/arm64"},
		},
		{
			name: "unrelated selector does not infer a platform",
			spec: &corev1.PodSpec{NodeSelector: map[string]string{
				"node.kubernetes.io/instance-type": "c7g.large",
			}},
		},
		{
			name: "architecture without OS remains ambiguous",
			spec: &corev1.PodSpec{NodeSelector: map[string]string{
				stableArchLabel: "arm64",
			}},
		},
		{
			name: "required affinity with multiple architectures",
			spec: &corev1.PodSpec{Affinity: requiredNodeAffinity(
				nodeTerm(
					inRequirement(stableOSLabel, "linux"),
					inRequirement(stableArchLabel, "arm64", "amd64"),
				),
			)},
			want: []string{"linux/amd64", "linux/arm64"},
		},
		{
			name: "required affinity OR terms",
			spec: &corev1.PodSpec{Affinity: requiredNodeAffinity(
				nodeTerm(
					inRequirement(stableOSLabel, "windows"),
					inRequirement(stableArchLabel, "amd64"),
				),
				nodeTerm(
					inRequirement(stableOSLabel, "linux"),
					inRequirement(stableArchLabel, "arm64"),
				),
			)},
			want: []string{"linux/arm64", "windows/amd64"},
		},
		{
			name: "node selector intersects required affinity",
			spec: &corev1.PodSpec{
				NodeSelector: map[string]string{stableOSLabel: "linux"},
				Affinity: requiredNodeAffinity(nodeTerm(
					inRequirement(stableOSLabel, "linux", "windows"),
					inRequirement(stableArchLabel, "arm64"),
				)),
			},
			want: []string{"linux/arm64"},
		},
		{
			name: "conflicting selector and affinity is not guessed",
			spec: &corev1.PodSpec{
				NodeSelector: map[string]string{stableOSLabel: "linux"},
				Affinity: requiredNodeAffinity(nodeTerm(
					inRequirement(stableOSLabel, "windows"),
					inRequirement(stableArchLabel, "amd64"),
				)),
			},
		},
		{
			name: "ambiguous OR branch invalidates partial answer",
			spec: &corev1.PodSpec{Affinity: requiredNodeAffinity(
				nodeTerm(
					inRequirement(stableOSLabel, "linux"),
					inRequirement(stableArchLabel, "arm64"),
				),
				nodeTerm(inRequirement("topology.kubernetes.io/zone", "east")),
			)},
		},
		{
			name: "NotIn architecture is ambiguous",
			spec: &corev1.PodSpec{Affinity: requiredNodeAffinity(nodeTerm(
				inRequirement(stableOSLabel, "linux"),
				corev1.NodeSelectorRequirement{
					Key:      stableArchLabel,
					Operator: corev1.NodeSelectorOpNotIn,
					Values:   []string{"amd64"},
				},
			))},
		},
		{
			name: "Exists OS is ambiguous",
			spec: &corev1.PodSpec{Affinity: requiredNodeAffinity(nodeTerm(
				corev1.NodeSelectorRequirement{
					Key:      stableOSLabel,
					Operator: corev1.NodeSelectorOpExists,
				},
				inRequirement(stableArchLabel, "amd64"),
			))},
		},
		{
			name: "empty required terms are unschedulable",
			spec: &corev1.PodSpec{Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{},
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, platformsFromSchedulingConstraints(tt.spec))
		})
	}
}

func requiredNodeAffinity(terms ...corev1.NodeSelectorTerm) *corev1.Affinity {
	return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: terms},
	}}
}

func nodeTerm(requirements ...corev1.NodeSelectorRequirement) corev1.NodeSelectorTerm {
	return corev1.NodeSelectorTerm{MatchExpressions: requirements}
}

func inRequirement(key string, values ...string) corev1.NodeSelectorRequirement {
	return corev1.NodeSelectorRequirement{
		Key: key, Operator: corev1.NodeSelectorOpIn, Values: values,
	}
}

func TestInferWorkloadPlatforms(t *testing.T) {
	nodes := map[string]string{
		"amd-worker": "linux/amd64",
		"arm-worker": "linux/arm64",
	}

	tests := []struct {
		name string
		spec map[string]any
		want []string
	}{
		{
			name: "scheduled Node wins over a conflicting selector",
			spec: map[string]any{
				"nodeName": "arm-worker",
				"nodeSelector": map[string]any{
					stableOSLabel: "linux", stableArchLabel: "amd64",
				},
			},
			want: []string{"linux/arm64"},
		},
		{
			name: "unknown scheduled Node falls back to selector",
			spec: map[string]any{
				"nodeName": "not-collected",
				"nodeSelector": map[string]any{
					stableOSLabel: "linux", stableArchLabel: "amd64",
				},
			},
			want: []string{"linux/amd64"},
		},
		{
			name: "unconstrained workload covers every observed Node platform",
			spec: map[string]any{},
			want: []string{"linux/amd64", "linux/arm64"},
		},
		{
			name: "partial selector filters observed Node platforms",
			spec: map[string]any{
				"nodeSelector": map[string]any{stableArchLabel: "arm64"},
			},
			want: []string{"linux/arm64"},
		},
		{
			name: "NotIn excludes observed Node platforms",
			spec: map[string]any{
				"affinity": map[string]any{
					"nodeAffinity": map[string]any{
						"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{
							"nodeSelectorTerms": []any{
								map[string]any{"matchExpressions": []any{
									map[string]any{"key": stableArchLabel, "operator": "NotIn", "values": []any{"amd64"}},
								}},
							},
						},
					},
				},
			},
			want: []string{"linux/arm64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload := platformTestPod("app", "example/app:latest", tt.spec)
			assert.Equal(t, tt.want, inferWorkloadPlatforms(workload, nodes))
		})
	}

	assert.Nil(t, inferWorkloadPlatforms(nil, nodes))
	assert.Empty(t, inferWorkloadPlatforms(platformTestPod("offline", "example/app:latest", nil), nil))
}

func TestCollectImageScanTargetsUsesPlatformOverride(t *testing.T) {
	pod := platformTestPod("app", "example/app:latest", map[string]any{
		"nodeSelector": map[string]any{
			stableOSLabel: "linux", stableArchLabel: "arm64",
		},
	})
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[pod.GetID()] = pod

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeFramework,
		scanData,
		context.Background(),
		cautils.ContextFile,
		nil,
		"linux/amd64",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/amd64",
	}), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsUsesScheduledNodePlatform(t *testing.T) {
	node := platformTestNode("arm-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "arm64",
	}, "", "")
	pod := platformTestPod("app", "example/app:latest", map[string]any{
		"nodeName": "arm-worker",
	})
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[node.GetID()] = node
	scanData.AllResources[pod.GetID()] = pod

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeCluster,
		scanData,
		context.Background(),
		cautils.ContextCluster,
		nil,
		"",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64",
	}), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsCoversHeterogeneousCluster(t *testing.T) {
	amd := platformTestNode("amd-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "amd64",
	}, "", "")
	arm := platformTestNode("arm-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "arm64",
	}, "", "")
	pod := platformTestPod("app", "example/app:latest", nil)
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[amd.GetID()] = amd
	scanData.AllResources[arm.GetID()] = arm
	scanData.AllResources[pod.GetID()] = pod

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeCluster,
		scanData,
		context.Background(),
		cautils.ContextCluster,
		nil,
		"",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(
		ImageScanTarget{Image: "example/app:latest", Platform: "linux/amd64", SkipUnavailable: true},
		ImageScanTarget{Image: "example/app:latest", Platform: "linux/arm64", SkipUnavailable: true},
	), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsDoesNotScanExcludedPlatform(t *testing.T) {
	amd := platformTestNode("amd-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "amd64",
	}, "", "")
	arm := platformTestNode("arm-worker", map[string]string{
		stableOSLabel: "linux", stableArchLabel: "arm64",
	}, "", "")
	pod := platformTestPod("app", "example/app:latest", map[string]any{
		"affinity": map[string]any{
			"nodeAffinity": map[string]any{
				"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{
					"nodeSelectorTerms": []any{
						map[string]any{"matchExpressions": []any{
							map[string]any{"key": stableArchLabel, "operator": "NotIn", "values": []any{"amd64"}},
						}},
					},
				},
			},
		},
	})
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[amd.GetID()] = amd
	scanData.AllResources[arm.GetID()] = arm
	scanData.AllResources[pod.GetID()] = pod

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeCluster, scanData, context.Background(), cautils.ContextCluster, nil, "",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64",
	}), collectedTargetSet(targets))
}

func TestAddImageScanTargetRequiredVariantWins(t *testing.T) {
	targets := mapset.NewSet[ImageScanTarget]()
	addImageScanTarget(targets, ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64", SkipUnavailable: true,
	})
	addImageScanTarget(targets, ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64",
	})

	assert.Equal(t, targetSet(ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64",
	}), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsPreservesProviderDefaultWithoutEvidence(t *testing.T) {
	pod := platformTestPod("app", "example/app:latest", nil)
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[pod.GetID()] = pod

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeFramework,
		scanData,
		context.Background(),
		cautils.ContextFile,
		nil,
		"",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(ImageScanTarget{Image: "example/app:latest"}), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsDeduplicatesSameVariant(t *testing.T) {
	first := platformTestPod("first", "example/shared:latest", map[string]any{
		"nodeSelector": map[string]any{stableOSLabel: "linux", stableArchLabel: "arm64"},
	})
	second := platformTestPod("second", "example/shared:latest", map[string]any{
		"nodeSelector": map[string]any{stableOSLabel: "linux", stableArchLabel: "arm64"},
	})
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[first.GetID()] = first
	scanData.AllResources[second.GetID()] = second

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeFramework,
		scanData,
		context.Background(),
		cautils.ContextFile,
		nil,
		"",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(ImageScanTarget{
		Image: "example/shared:latest", Platform: "linux/arm64",
	}), collectedTargetSet(targets))
}

func TestCollectImageScanTargetsKeepsDifferentVariants(t *testing.T) {
	amd := platformTestPod("amd", "example/shared:latest", map[string]any{
		"nodeSelector": map[string]any{stableOSLabel: "linux", stableArchLabel: "amd64"},
	})
	arm := platformTestPod("arm", "example/shared:latest", map[string]any{
		"nodeSelector": map[string]any{stableOSLabel: "linux", stableArchLabel: "arm64"},
	})
	scanData := cautils.NewOPASessionObjMock()
	scanData.AllResources[amd.GetID()] = amd
	scanData.AllResources[arm.GetID()] = arm

	targets, _, errs := collectImageScanTargets(
		cautils.ScanTypeFramework,
		scanData,
		context.Background(),
		cautils.ContextFile,
		nil,
		"",
	)

	require.Empty(t, errs)
	assert.Equal(t, targetSet(
		ImageScanTarget{Image: "example/shared:latest", Platform: "linux/amd64"},
		ImageScanTarget{Image: "example/shared:latest", Platform: "linux/arm64"},
	), collectedTargetSet(targets))
}

func TestImageScanTargetString(t *testing.T) {
	assert.Equal(t, "example/app:latest", (ImageScanTarget{Image: "example/app:latest"}).String())
	assert.Equal(t, "example/app:latest [linux/arm64]", (ImageScanTarget{
		Image: "example/app:latest", Platform: "linux/arm64",
	}).String())
}

func TestPlatformConstraintIgnoresMatchFields(t *testing.T) {
	spec := &corev1.PodSpec{Affinity: requiredNodeAffinity(corev1.NodeSelectorTerm{
		MatchExpressions: []corev1.NodeSelectorRequirement{
			inRequirement(stableOSLabel, "linux"),
			inRequirement(stableArchLabel, "amd64"),
		},
		MatchFields: []corev1.NodeSelectorRequirement{{
			Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-1"},
		}},
	})}

	assert.Equal(t, []string{"linux/amd64"}, platformsFromSchedulingConstraints(spec))
}

func TestPreferredAffinityDoesNotNarrowHardPlatformSet(t *testing.T) {
	workload := platformTestPod("preferred", "example/app:latest", map[string]any{
		"affinity": map[string]any{
			"nodeAffinity": map[string]any{
				"preferredDuringSchedulingIgnoredDuringExecution": []any{
					map[string]any{
						"weight": 100,
						"preference": map[string]any{
							"matchExpressions": []any{
								map[string]any{"key": stableOSLabel, "operator": "In", "values": []any{"linux"}},
								map[string]any{"key": stableArchLabel, "operator": "In", "values": []any{"arm64"}},
							},
						},
					},
				},
			},
		},
	})

	assert.Equal(t, []string{"linux/amd64", "linux/arm64"}, inferWorkloadPlatforms(workload, map[string]string{
		"amd": "linux/amd64",
		"arm": "linux/arm64",
	}))
}

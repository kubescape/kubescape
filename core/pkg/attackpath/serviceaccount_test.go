package attackpath

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// automountBoolPtr is a test helper: the Kubernetes API uses *bool for
// automountServiceAccountToken so that unset (nil) is distinguishable
// from explicitly false.
func automountBoolPtr(b bool) *bool { return &b }

// workloadObj builds a Deployment IMetadata with the given pod-spec fields
// set, for ServiceAccount binding tests.
func workloadWithSA(namespace, name, saName string, automount *bool, volumes []any) workloadinterface.IMetadata {
	podSpec := map[string]any{"containers": []any{map[string]any{"name": "app", "image": "test"}}}
	if saName != "" {
		podSpec["serviceAccountName"] = saName
	}
	if automount != nil {
		podSpec["automountServiceAccountToken"] = *automount
	}
	if len(volumes) > 0 {
		podSpec["volumes"] = volumes
		podSpec["containers"] = []any{map[string]any{"name": "app", "image": "test", "volumeMounts": []any{map[string]any{"name": "kube-api-access", "mountPath": "/token"}}}}
	}
	return resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": name}},
				"spec":     podSpec,
			},
		},
	})
}

// projectedSATokenVolume returns a volume entry that carries a projected
// serviceAccountToken source — simulating an explicitly-requested token
// mount regardless of automountServiceAccountToken settings.
func projectedSATokenVolume() map[string]any {
	return map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
}

// automountSAIndex is a shorthand to build the automount index from ServiceAccount
// typed objects, the same way production code builds it via
// ServiceAccountAutomountIndex.
func automountSAIndex(sas ...corev1.ServiceAccount) map[string]*bool {
	return ServiceAccountAutomountIndex(sas)
}

func automountSAObj(namespace, name string, automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Namespace: namespace, Name: name},
		AutomountServiceAccountToken: automount,
	}
}

// resultFor finds the ServiceAccountBinding for a given workload name in
// the results slice. Fails the test if not found.
func resultFor(t *testing.T, results []ServiceAccountBinding, name string) ServiceAccountBinding {
	t.Helper()
	for _, r := range results {
		if r.WorkloadRef.Name == name {
			return r
		}
	}
	t.Fatalf("no binding result found for workload %q", name)
	return ServiceAccountBinding{}
}

// --- ServiceAccountAutomountIndex tests ---

func TestServiceAccountAutomountIndex_NilAutomountStoredAsNilPointer(t *testing.T) {
	idx := automountSAIndex(automountSAObj("prod", "app", nil))
	v, ok := idx["prod/app"]
	if !ok {
		t.Fatal("expected prod/app in index")
	}
	if v != nil {
		t.Errorf("expected nil pointer for SA with no automount field, got %v", *v)
	}
}

func TestServiceAccountAutomountIndex_FalseStoredCorrectly(t *testing.T) {
	idx := automountSAIndex(automountSAObj("prod", "restricted", automountBoolPtr(false)))
	v := idx["prod/restricted"]
	if v == nil || *v != false {
		t.Errorf("expected *false for restricted SA, got %v", v)
	}
}

func TestServiceAccountAutomountIndex_TrueStoredCorrectly(t *testing.T) {
	idx := automountSAIndex(automountSAObj("prod", "permissive", automountBoolPtr(true)))
	v := idx["prod/permissive"]
	if v == nil || *v != true {
		t.Errorf("expected *true for permissive SA, got %v", v)
	}
}

// --- ResolveServiceAccountBindings golden-file cases (proposal §7) ---

func TestResolveServiceAccountBindings_DefaultSAAndKubernetesDefaultMountTrue(t *testing.T) {
	// Collected default SA, with no automount field set → resolves to
	// "default" SA with TokenMounted=true (the Kubernetes default).
	w := workloadWithSA("prod", "web", "", nil, nil)
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex(automountSAObj("prod", "default", nil)))

	r := resultFor(t, results, "web")
	if r.ServiceAccountName != "default" {
		t.Errorf("expected SA name 'default', got %q", r.ServiceAccountName)
	}
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true when nothing opts out (Kubernetes default)")
	}
}

func TestResolveServiceAccountBindings_PodLevelFalseWins(t *testing.T) {
	// automountServiceAccountToken: false at the pod level → TokenMounted=false,
	// regardless of what the SA says. This is golden-file case 1 from proposal §7.
	w := workloadWithSA("prod", "secure", "my-sa", automountBoolPtr(false), nil)
	results := ResolveServiceAccountBindings(
		makeResources(w),
		automountSAIndex(automountSAObj("prod", "my-sa", automountBoolPtr(true))), // SA says true; pod overrides
	)

	r := resultFor(t, results, "secure")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: pod-level false must win over SA-level true")
	}
}

func TestResolveServiceAccountBindings_SALevelFalseAppliesWhenPodNotSet(t *testing.T) {
	// No pod-level automount set; SA has automountServiceAccountToken: false
	// → TokenMounted=false. Golden-file case 2 from proposal §7.
	w := workloadWithSA("prod", "worker", "restricted-sa", nil, nil)
	results := ResolveServiceAccountBindings(
		makeResources(w),
		automountSAIndex(automountSAObj("prod", "restricted-sa", automountBoolPtr(false))),
	)

	r := resultFor(t, results, "worker")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: SA-level false must apply when pod level is unset")
	}
}

func TestResolveServiceAccountBindings_ProjectedTokenVolumeWinsOverPodFalse(t *testing.T) {
	// automountServiceAccountToken: false at the pod level, BUT a projected
	// serviceAccountToken volume is explicitly present → TokenMounted=true.
	// This is the critical golden-file case from proposal §7: the token IS
	// mounted because it was explicitly projected, overriding the automount flag.
	w := workloadWithSA("prod", "explicit", "my-sa", automountBoolPtr(false),
		[]any{projectedSATokenVolume()})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())

	r := resultFor(t, results, "explicit")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: projected serviceAccountToken volume is present, overriding automount=false")
	}
}

func TestResolveServiceAccountBindings_ProjectedTokenVolumeWinsOverSAFalse(t *testing.T) {
	// SA-level automountServiceAccountToken: false, no pod-level override,
	// but a projected volume is present → TokenMounted=true.
	// Complements the pod-level case above; both must hold.
	w := workloadWithSA("prod", "projected-only", "no-mount-sa", nil,
		[]any{projectedSATokenVolume()})
	results := ResolveServiceAccountBindings(
		makeResources(w),
		automountSAIndex(automountSAObj("prod", "no-mount-sa", automountBoolPtr(false))),
	)

	r := resultFor(t, results, "projected-only")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: projected volume wins over SA-level automount=false")
	}
}

func TestResolveServiceAccountBindings_ExplicitSANameCarriedThrough(t *testing.T) {
	w := workloadWithSA("prod", "api", "custom-sa", nil, nil)
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())

	r := resultFor(t, results, "api")
	if r.ServiceAccountName != "custom-sa" {
		t.Errorf("expected SA name 'custom-sa', got %q", r.ServiceAccountName)
	}
	if r.Namespace != "prod" {
		t.Errorf("expected Namespace 'prod', got %q", r.Namespace)
	}
}

func TestResolveServiceAccountBindings_NonWorkloadKindIsIgnored(t *testing.T) {
	// A Service in the resource map must be ignored: only kinds in
	// WorkloadKindGVRs produce bindings.
	svc := resource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "svc", "namespace": "prod"},
		"spec":       map[string]any{"selector": map[string]any{"app": "web"}},
	})
	results := ResolveServiceAccountBindings(makeResources(svc), automountSAIndex())
	if len(results) != 0 {
		t.Errorf("expected no results for a non-workload kind, got %+v", results)
	}
}

func TestResolveServiceAccountBindings_OutputIsDeterministic(t *testing.T) {
	// Multiple workloads: results must be in resource-ID order on every run.
	a := workloadWithSA("alpha", "app", "sa-a", nil, nil)
	b := workloadWithSA("beta", "app", "sa-b", nil, nil)
	c := workloadWithSA("alpha", "worker", "sa-c", nil, nil)

	first := ResolveServiceAccountBindings(makeResources(a, b, c), automountSAIndex())
	second := ResolveServiceAccountBindings(makeResources(a, b, c), automountSAIndex())

	if len(first) != len(second) {
		t.Fatalf("run lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].WorkloadRef != second[i].WorkloadRef {
			t.Errorf("position %d differs between runs: %+v vs %+v", i, first[i].WorkloadRef, second[i].WorkloadRef)
		}
	}
}

func TestResolveServiceAccountBindings_EmptyResourcesReturnsEmpty(t *testing.T) {
	results := ResolveServiceAccountBindings(map[string]workloadinterface.IMetadata{}, automountSAIndex())
	if len(results) != 0 {
		t.Errorf("expected empty result for empty resources, got %+v", results)
	}
}

func TestResolveServiceAccountBindings_ProjectedVolumeNotMountedByContainer(t *testing.T) {
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "no-mount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "no-mount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "no-mount")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: projected volume declared but not mounted by any container")
	}
}

func TestResolveServiceAccountBindings_ProjectedVolumeMountedByContainer(t *testing.T) {
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "with-mount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "with-mount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "with-mount")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: projected volume mounted by container")
	}
}

func TestResolveServiceAccountBindings_NativeSidecarMountsMakeTokenMounted(t *testing.T) {
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "sidecar-mount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "sidecar-mount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx"},
					},
					"initContainers": []any{
						map[string]any{
							"name":          "token-sidecar",
							"image":         "busybox",
							"restartPolicy": "Always",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "sidecar-mount")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: native sidecar init-container mounts the projected token")
	}
}

func TestResolveServiceAccountBindings_NullAutomountUsesDefault(t *testing.T) {
	// automountServiceAccountToken: null must be treated as unset,
	// falling through to the Kubernetes default of true.
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "null-automount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "null-automount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": nil,
					"containers":                   []any{map[string]any{"name": "app", "image": "test"}},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex(automountSAObj("prod", "default", nil)))
	r := resultFor(t, results, "null-automount")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: null automount must fall through to Kubernetes default")
	}
}

func TestResolveServiceAccountBindings_AutomountBlockedByExistingMount(t *testing.T) {
	// automountServiceAccountToken: true but the default token path is
	// already occupied — Kubernetes admission skips injection.
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "blocked-mount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "blocked-mount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": true,
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":      "custom-vol",
									"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "blocked-mount")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: existing mount at token path blocks automatic injection")
	}
}

func TestReviewProjectedTokenExcludedBySubPath(t *testing.T) {
	makeObj := func(subPath string) map[string]any {
		mount := map[string]any{
			"name":      "identity",
			"mountPath": "/var/meta",
		}
		if subPath != "" {
			mount["subPath"] = subPath
		}
		return map[string]any{
			"kind": "Pod",
			"spec": map[string]any{
				"automountServiceAccountToken": false,
				"serviceAccountName":           "my-sa",
				"volumes": []any{
					map[string]any{
						"name": "identity",
						"projected": map[string]any{
							"sources": []any{
								map[string]any{
									"serviceAccountToken": map[string]any{
										"path":              "token",
										"expirationSeconds": int64(3600),
									},
								},
								map[string]any{
									"downwardAPI": map[string]any{
										"items": []any{
											map[string]any{
												"path":     "namespace",
												"fieldRef": map[string]any{"fieldPath": "metadata.namespace"},
											},
										},
									},
								},
							},
						},
					},
				},
				"containers": []any{
					map[string]any{
						"name":         "app",
						"image":        "busybox",
						"volumeMounts": []any{mount},
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		subPath string
		want    bool
	}{
		{"sibling subPath excludes token", "namespace", false},
		{"token subPath exposes token", "token", true},
		{"whole-volume mount exposes token", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := makeObj(tt.subPath)
			obj["apiVersion"] = "v1"
			obj["metadata"] = map[string]any{"name": "subpath", "namespace": "prod"}
			r := resultFor(t, ResolveServiceAccountBindings(makeResources(resource(obj)), nil), "subpath")
			if got := r.TokenMounted; got != tt.want {
				t.Errorf("subPath=%q: got %v, want %v", tt.subPath, got, tt.want)
			}
		})
	}
}

func TestResolveServiceAccountBindings_SubpathDotRootIsTokenAccess(t *testing.T) {
	// subPath: "." selects the volume root, which includes the token file.
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "dot-root", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "dot-root"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/custom",
									"subPath":   ".",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "dot-root")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: subPath \".\" selects volume root including token")
	}
}

func TestResolveServiceAccountBindings_SubpathDotTokenIsTokenAccess(t *testing.T) {
	// subPath: "./token" normalizes to "token" — same as the token file path.
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "dot-token", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "dot-token"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/custom",
									"subPath":   "./token",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "dot-token")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: subPath \"./token\" normalizes to \"token\"")
	}
}

func TestResolveServiceAccountBindings_LiteralSubPathExprSiblingNotTokenAccess(t *testing.T) {
	// subPathExpr: "namespace" is a literal (no $() substitution) that
	// selects only the namespace sibling file, not the token.
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
				map[string]any{
					"downwardAPI": map[string]any{
						"items": []any{
							map[string]any{
								"path": "namespace",
								"fieldRef": map[string]any{
									"apiVersion": "v1",
									"fieldPath":  "metadata.namespace",
								},
							},
						},
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "expr-sibling", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "expr-sibling"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":        "kube-api-access",
									"mountPath":   "/custom",
									"subPathExpr": "namespace",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "expr-sibling")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: literal subPathExpr \"namespace\" selects only the namespace sibling")
	}
}

func TestResolveServiceAccountBindings_SubpathAncestorDirectoryIsTokenAccess(t *testing.T) {
	// subPath: "identity" is an ancestor directory of token path "identity/token".
	// Uses path.Clean (slash-only) so this works correctly on Windows hosts too.
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "identity/token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "ancestor-dir", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "ancestor-dir"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/custom",
									"subPath":   "identity",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "ancestor-dir")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: subPath \"identity\" is an ancestor of token path \"identity/token\"")
	}
}

func TestResolveServiceAccountBindings_SkipsMissingPodSpec(t *testing.T) {
	// A Deployment with an empty spec should be skipped, not reported as
	// TokenMounted: true with the default SA.
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "empty-spec", "namespace": "prod"},
		"spec":       map[string]any{},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "empty-spec")
	if !r.Skipped {
		t.Errorf("expected Skipped=true for Deployment with missing pod spec, got TokenMounted=%v", r.TokenMounted)
	}
}

func TestResolveServiceAccountBindings_LegacyServiceAccountField(t *testing.T) {
	// Older manifests use "serviceAccount" instead of "serviceAccountName".
	// The resolver must read it before falling back to "default".
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "legacy-sa", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "legacy-sa"}},
				"spec": map[string]any{
					"serviceAccount": "my-sa",
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx"},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "legacy-sa")
	if r.ServiceAccountName != "my-sa" {
		t.Errorf("expected ServiceAccountName=my-sa (from legacy field), got %q", r.ServiceAccountName)
	}
}

func TestResolveServiceAccountBindings_EphemeralContainerMountsMakeTokenMounted(t *testing.T) {
	// An ephemeral (debug) container that mounts a projected token volume must
	// cause TokenMounted=true, even when regular and init containers do not.
	vol := map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": int64(3607),
						"path":              "token",
					},
				},
			},
		},
	}
	w := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "ephemeral-mount", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "ephemeral-mount"}},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"volumes":                      []any{vol},
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx",
							// No volumeMounts — regular container does NOT mount the token.
						},
					},
					"ephemeralContainers": []any{
						map[string]any{
							"name":  "debugger",
							"image": "busybox",
							"volumeMounts": []any{
								map[string]any{
									"name":      "kube-api-access",
									"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
								},
							},
						},
					},
				},
			},
		},
	})
	results := ResolveServiceAccountBindings(makeResources(w), automountSAIndex())
	r := resultFor(t, results, "ephemeral-mount")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: ephemeral container mounts the projected token volume")
	}
}

func TestResolveServiceAccountBindings_ServiceAccountAvailability(t *testing.T) {
	for _, tc := range []struct {
		name                string
		index               map[string]*bool
		podAutomount        *bool
		projected, occupied bool
		mounted, unknown    bool
	}{
		{name: "missing account", unknown: true},
		{name: "collected unset account", index: map[string]*bool{"prod/custom": nil}, mounted: true},
		{name: "collected disabled account", index: map[string]*bool{"prod/custom": automountBoolPtr(false)}},
		{name: "pod enables without account", podAutomount: automountBoolPtr(true), mounted: true},
		{name: "pod disables without account", podAutomount: automountBoolPtr(false)},
		{name: "projected token without account", projected: true, mounted: true},
		{name: "occupied path without account", occupied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := map[string]any{"serviceAccountName": "custom"}
			container := map[string]any{"name": "app", "image": "test"}
			if tc.podAutomount != nil {
				spec["automountServiceAccountToken"] = *tc.podAutomount
			}
			if tc.projected {
				spec["volumes"] = []any{projectedSATokenVolume()}
				container["volumeMounts"] = []any{map[string]any{"name": "kube-api-access", "mountPath": "/token"}}
			}
			if tc.occupied {
				container["volumeMounts"] = []any{map[string]any{"name": "other", "mountPath": serviceAccountTokenMountPath}}
			}
			spec["containers"] = []any{container}
			w := resource(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "web", "namespace": "prod"}, "spec": spec})
			r := resultFor(t, ResolveServiceAccountBindings(makeResources(w), tc.index), "web")
			if r.TokenMounted != tc.mounted || r.TokenUnknown != tc.unknown || r.Skipped || r.ServiceAccountName != "custom" {
				t.Fatalf("expected mounted=%v unknown=%v with resolved identity, got %+v", tc.mounted, tc.unknown, r)
			}
		})
	}
}

func TestResolveServiceAccountBindings_MirrorPodHasNoIdentity(t *testing.T) {
	w := resource(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"namespace": "kube-system", "name": "kube-apiserver", "annotations": map[string]any{"kubernetes.io/config.mirror": "hash"}},
		"spec":     map[string]any{"containers": []any{map[string]any{"name": "server", "image": "test"}}},
	})
	r := resultFor(t, ResolveServiceAccountBindings(makeResources(w), map[string]*bool{"kube-system/default": nil}), "kube-apiserver")
	if !r.Skipped || r.SkipReason == "" || r.ServiceAccountName != "" || r.TokenMounted {
		t.Fatalf("mirror Pod must not acquire a ServiceAccount identity: %+v", r)
	}
}

func TestResolveServiceAccountBindings_IdentityValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
	}{
		{"invalid name", map[string]any{"serviceAccountName": int64(7)}},
		{"invalid legacy name", map[string]any{"serviceAccount": false}},
		{"conflicting names", map[string]any{"serviceAccountName": "one", "serviceAccount": "two"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fields["containers"] = []any{map[string]any{"name": "app", "image": "test"}}
			w := resource(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "invalid", "namespace": "prod"}, "spec": tc.fields})
			r := resultFor(t, ResolveServiceAccountBindings(makeResources(w), map[string]*bool{"prod/default": nil}), "invalid")
			if !r.Skipped || r.SkipReason == "" || r.ServiceAccountName != "" || r.TokenMounted {
				t.Fatalf("invalid identity must be skipped with reason: %+v", r)
			}
		})
	}
}

func TestResolveServiceAccountBindings_TokenUncertaintyAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, field, value string
		automount          any
		mounted, unknown   bool
	}{
		{name: "malformed automount", automount: "false", unknown: true},
		{name: "environment expression", field: "subPathExpr", value: "$(FILE)", automount: false, unknown: true},
		{name: "automatic injection wins", field: "subPathExpr", value: "$(FILE)", automount: true, mounted: true},
		{name: "data root subpath", field: "subPath", value: "..data", automount: false, mounted: true},
		{name: "data token subpath", field: "subPath", value: "..data/token", automount: false, mounted: true},
		{name: "data root expression", field: "subPathExpr", value: "..data", automount: false, mounted: true},
		{name: "data token expression", field: "subPathExpr", value: "..data/token", automount: false, mounted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := map[string]any{"name": "app", "image": "test"}
			spec := map[string]any{"containers": []any{container}, "automountServiceAccountToken": tc.automount}
			if tc.field != "" {
				spec["volumes"] = []any{projectedSATokenVolume()}
				container["volumeMounts"] = []any{map[string]any{"name": "kube-api-access", "mountPath": "/token", tc.field: tc.value}}
			}
			w := resource(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "token", "namespace": "prod"}, "spec": spec})
			r := resultFor(t, ResolveServiceAccountBindings(makeResources(w), map[string]*bool{"prod/default": nil}), "token")
			if r.TokenMounted != tc.mounted || r.TokenUnknown != tc.unknown {
				t.Fatalf("want mounted=%v unknown=%v, got %+v", tc.mounted, tc.unknown, r)
			}
		})
	}
}

package pss

import (
	"testing"
)

func TestExtractPodSpec_WorkloadKinds(t *testing.T) {
	podTemplateSpec := map[string]any{
		"containers": []any{
			map[string]any{
				"name":  "test-container",
				"image": "nginx:alpine",
			},
		},
	}

	tests := []struct {
		kind string
		obj  map[string]any
	}{
		{
			kind: "Pod",
			obj: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "my-pod", "namespace": "default"},
				"spec":       podTemplateSpec,
			},
		},
		{
			kind: "Deployment",
			obj: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "my-dep", "namespace": "prod"},
				"spec": map[string]any{
					"template": map[string]any{
						"spec": podTemplateSpec,
					},
				},
			},
		},
		{
			kind: "DaemonSet",
			obj: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "DaemonSet",
				"metadata":   map[string]any{"name": "my-ds", "namespace": "kube-system"},
				"spec": map[string]any{
					"template": map[string]any{
						"spec": podTemplateSpec,
					},
				},
			},
		},
		{
			kind: "StatefulSet",
			obj: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "StatefulSet",
				"metadata":   map[string]any{"name": "my-sts", "namespace": "db"},
				"spec": map[string]any{
					"template": map[string]any{
						"spec": podTemplateSpec,
					},
				},
			},
		},
		{
			kind: "ReplicaSet",
			obj: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "ReplicaSet",
				"metadata":   map[string]any{"name": "my-rs", "namespace": "default"},
				"spec": map[string]any{
					"template": map[string]any{
						"spec": podTemplateSpec,
					},
				},
			},
		},
		{
			kind: "Job",
			obj: map[string]any{
				"apiVersion": "batch/v1",
				"kind":       "Job",
				"metadata":   map[string]any{"name": "my-job", "namespace": "batch"},
				"spec": map[string]any{
					"template": map[string]any{
						"spec": podTemplateSpec,
					},
				},
			},
		},
		{
			kind: "CronJob",
			obj: map[string]any{
				"apiVersion": "batch/v1",
				"kind":       "CronJob",
				"metadata":   map[string]any{"name": "my-cj", "namespace": "cron"},
				"spec": map[string]any{
					"jobTemplate": map[string]any{
						"spec": map[string]any{
							"template": map[string]any{
								"spec": podTemplateSpec,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			ps, err := ExtractPodSpec(tt.kind, tt.obj)
			if err != nil {
				t.Fatalf("ExtractPodSpec(%s) failed: %v", tt.kind, err)
			}
			if len(ps.Containers) != 1 {
				t.Fatalf("expected 1 container, got %d", len(ps.Containers))
			}
			if ps.Containers[0].Name != "test-container" {
				t.Errorf("expected container name test-container, got %q", ps.Containers[0].Name)
			}
			if ps.Containers[0].Image != "nginx:alpine" {
				t.Errorf("expected image nginx:alpine, got %q", ps.Containers[0].Image)
			}
		})
	}
}

func TestExtractPodSpec_UnsupportedKind(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "svc"},
		"spec":       map[string]any{},
	}

	_, err := ExtractPodSpec("Service", obj)
	if err == nil {
		t.Errorf("expected error for unsupported kind Service, got nil")
	}
}

func TestExtractPodSpec_MissingSpec(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "broken"},
		"spec":       map[string]any{}, // missing template.spec
	}

	_, err := ExtractPodSpec("Deployment", obj)
	if err == nil {
		t.Errorf("expected error for missing template.spec, got nil")
	}
}

func TestEvaluateUnstructured(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "hostnet-dep", "namespace": "sec"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostNetwork": true,
					"containers": []any{
						map[string]any{"name": "app", "image": "busybox"},
					},
				},
			},
		},
	}

	violations, err := EvaluateUnstructured("Deployment", obj, Baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundHostNet := false
	for _, v := range violations {
		if v.Check == "HostNetwork" {
			foundHostNet = true
			break
		}
	}
	if !foundHostNet {
		t.Errorf("expected HostNetwork violation, got: %+v", violations)
	}
}

func TestWorkloadResultFromUnstructured(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "web", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostPID": true,
					"containers": []any{
						map[string]any{"name": "web", "image": "nginx"},
					},
				},
			},
		},
	}

	res, err := WorkloadResultFromUnstructured("Deployment", "web", "prod", obj, Baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Kind != "Deployment" || res.Name != "web" || res.Namespace != "prod" {
		t.Errorf("unexpected workload identity: %+v", res)
	}
	if res.PassesAt != Privileged {
		t.Errorf("PassesAt = %v, want Privileged (has HostPID violation)", res.PassesAt)
	}
	if len(res.Violations) == 0 {
		t.Errorf("expected violations, got 0")
	}
}

func TestEvaluateUnstructured_LegacyAppArmor(t *testing.T) {
	t.Run("deployment template legacy apparmor annotation", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "app-dep", "namespace": "default"},
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]any{
							"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{"name": "app", "image": "nginx"},
						},
					},
				},
			},
		}

		violations, err := EvaluateUnstructured("Deployment", obj, Baseline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundAppArmor := false
		for _, v := range violations {
			if v.Check == "AppArmorProfile" {
				foundAppArmor = true
				break
			}
		}
		if !foundAppArmor {
			t.Errorf("expected AppArmorProfile violation from legacy annotation, got: %+v", violations)
		}
	})

	t.Run("pod metadata legacy apparmor annotation", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "app-pod",
				"namespace": "default",
				"annotations": map[string]any{
					"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
				},
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "app", "image": "nginx"},
				},
			},
		}

		violations, err := EvaluateUnstructured("Pod", obj, Baseline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundAppArmor := false
		for _, v := range violations {
			if v.Check == "AppArmorProfile" {
				foundAppArmor = true
				break
			}
		}
		if !foundAppArmor {
			t.Errorf("expected AppArmorProfile violation from Pod metadata annotation, got: %+v", violations)
		}
	})

	t.Run("forbidden legacy annotation triggers violation even if container specifies structured RuntimeDefault", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "app-dep", "namespace": "default"},
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]any{
							"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "app",
								"image": "nginx",
								"securityContext": map[string]any{
									"appArmorProfile": map[string]any{
										"type": "RuntimeDefault",
									},
								},
							},
						},
					},
				},
			},
		}

		violations, err := EvaluateUnstructured("Deployment", obj, Baseline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundAppArmor := false
		for _, v := range violations {
			if v.Check == "AppArmorProfile" {
				foundAppArmor = true
				break
			}
		}
		if !foundAppArmor {
			t.Errorf("expected AppArmorProfile violation even when container specifies structured RuntimeDefault, got: %+v", violations)
		}
	})

	t.Run("stale annotation on template triggers Baseline violation", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "app-dep", "namespace": "default"},
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]any{
							"container.apparmor.security.beta.kubernetes.io/absent-container": "docker/default",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{"name": "app", "image": "nginx"},
						},
					},
				},
			},
		}

		violations, err := EvaluateUnstructured("Deployment", obj, Baseline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundAppArmor := false
		for _, v := range violations {
			if v.Check == "AppArmorProfile" {
				foundAppArmor = true
				break
			}
		}
		if !foundAppArmor {
			t.Errorf("expected AppArmorProfile violation for absent-container docker/default annotation, got: %+v", violations)
		}
	})
}

func TestWorkloadResultFromUnstructured_LegacyAppArmor(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "apparmor-dep", "namespace": "default"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{
						"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
					},
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx"},
					},
				},
			},
		},
	}

	res, err := WorkloadResultFromUnstructured("Deployment", "apparmor-dep", "default", obj, Baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.PassesAt != Privileged {
		t.Errorf("PassesAt = %v, want Privileged (legacy unconfined AppArmor annotation)", res.PassesAt)
	}
	found := false
	for _, v := range res.Violations {
		if v.Check == "AppArmorProfile" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected AppArmorProfile violation in WorkloadResult, got: %+v", res.Violations)
	}
}

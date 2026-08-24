package opaprocessor

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestGetKubernetesObjectsDeduplicatesResourceAliases(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "agents.x-k8s.io/v1alpha1",
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":      "agent-sandbox",
			"namespace": "default",
		},
	})
	resourceID := workload.GetID()
	resources := cautils.K8SResources{
		"agents.x-k8s.io/v1alpha1/sandbox":   {resourceID},
		"agents.x-k8s.io/v1alpha1/sandboxes": {resourceID},
	}
	allResources := map[string]workloadinterface.IMetadata{resourceID: workload}
	match := []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"agents.x-k8s.io"},
		APIVersions: []string{"v1alpha1"},
		Resources:   []string{"Sandbox", "sandboxes"},
	}}

	objects := getKubernetesObjects(newResourceGroupIndex(resources, allResources), match)
	assert.Equal(t, 1, len(objects))
}

func TestGetKubernetesObjectsMatchesFutureAPIVersionWithWildcards(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "autoscaling/v99",
		"kind":       "HorizontalPodAutoscaler",
		"metadata": map[string]any{
			"name":      "future-hpa",
			"namespace": "default",
		},
	})
	resourceID := workload.GetID()
	resources := cautils.K8SResources{
		"autoscaling/v99/horizontalpodautoscaler": {resourceID},
	}
	allResources := map[string]workloadinterface.IMetadata{resourceID: workload}
	match := []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"HorizontalPodAutoscaler"},
	}}

	objects := getKubernetesObjects(newResourceGroupIndex(resources, allResources), match)
	require.Len(t, objects, 1)
	assert.Same(t, workload, objects[0])
}

func TestRemoveData(t *testing.T) {
	type args struct {
		w string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "remove data",
			args: args{
				w: `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"demoservice-server", "annotations": {"name": "kubectl.kubernetes.io/last-applied-configuration", "value": "blabla"}},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"demoservice-server"}},"template":{"metadata":{"creationTimestamp":null,"labels":{"app":"demoservice-server"}},"spec":{"containers":[{"env":[{"name":"SERVER_PORT","value":"8089"},{"name":"SLEEP_DURATION","value":"1"},{"name":"DEMO_FOLDERS","value":"/app"},{"name":"ARMO_TEST_NAME","value":"auto_attach_deployment"},{"name":"CAA_ENABLE_CRASH_REPORTER","value":"1"}],"image":"quay.io/armosec/demoservice:v25","imagePullPolicy":"IfNotPresent","name":"demoservice","ports":[{"containerPort":8089,"protocol":"TCP"}],"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File"}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"terminationGracePeriodSeconds":30}}}}`,
			},
		},
		{
			name: "remove data with init containers and ephemeral containers",
			args: args{
				w: `{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "example-pod", "namespace": "default"}, "spec": {"containers": [{"name": "container1", "image": "nginx", "ports": [{"containerPort": 80}], "env": [{"name": "CONTAINER_ENV", "value": "container_value"}]}], "initContainers": [{"name": "init-container1", "image": "busybox", "command": ["sh", "-c", "echo 'Init Container'"], "env": [{"name": "INIT_CONTAINER_ENV", "value": "init_container_value"}]}], "ephemeralContainers": [{"name": "debug-container", "image": "busybox", "command": ["sh", "-c", "echo 'Ephemeral Container'"], "targetContainerName": "container1", "env": [{"name": "EPHEMERAL_CONTAINER_ENV", "value": "ephemeral_container_value"}]}]}}`,
			},
		},
		{
			name: "remove secret data",
			args: args{
				w: `{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "example-secret", "namespace": "default", "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}}, "type": "Opaque", "data": {"username": "dXNlcm5hbWU=", "password": "cGFzc3dvcmQ="}}`,
			},
		},
		{
			name: "remove secret stringData",
			args: args{
				w: `{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "example-secret", "namespace": "default"}, "type": "Opaque", "stringData": {"token": "supersecret", "apiKey": "abc123"}}`,
			},
		},
		{
			name: "remove configMap data and binaryData",
			args: args{
				w: `{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "example-configmap", "namespace": "default", "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}}, "data": {"exampleKey": "exampleValue"}, "binaryData": {"example.bin": "dGVzdA=="}}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, _ := workloadinterface.NewWorkload([]byte(tt.args.w))
			removeData(obj)

			workload := workloadinterface.NewWorkloadObj(obj.GetObject())

			_, found := workload.GetAnnotation("kubectl.kubernetes.io/last-applied-configuration")
			assert.False(t, found)

			_, found = workloadinterface.InspectMap(workload.GetObject(), "metadata", "managedFields")
			assert.False(t, found)

			_, found = workloadinterface.InspectMap(workload.GetObject(), "status")
			assert.False(t, found)

			if d, ok := workloadinterface.InspectMap(workload.GetObject(), "data"); ok {
				data, ok := d.(map[string]any)
				assert.True(t, ok)
				for key := range data {
					assert.Equal(t, "XXXXXX", data[key])
				}
			}

			if sd, ok := workloadinterface.InspectMap(workload.GetObject(), "stringData"); ok {
				stringData, ok := sd.(map[string]any)
				assert.True(t, ok)
				for key := range stringData {
					assert.Equalf(t, "XXXXXX", stringData[key], "stringData[%q] was not redacted", key)
				}
			}

			if bd, ok := workloadinterface.InspectMap(workload.GetObject(), "binaryData"); ok {
				binaryData, ok := bd.(map[string]any)
				assert.True(t, ok)
				for key := range binaryData {
					assert.Equalf(t, "XXXXXX", binaryData[key], "binaryData[%q] was not redacted", key)
				}
			}

			if c, _ := workload.GetContainers(); c != nil {
				for i := range c {
					for _, e := range c[i].Env {
						assert.Equal(t, "XXXXXX", e.Value, e.Name)
					}
				}
			}

			if ic, _ := workload.GetInitContainers(); ic != nil {
				for i := range ic {
					for _, e := range ic[i].Env {
						assert.Equal(t, "XXXXXX", e.Value, e.Name)
					}
				}
			}

			if ec, _ := workload.GetEphemeralContainers(); ec != nil {
				for i := range ec {
					for _, e := range ec[i].Env {
						assert.Equal(t, "XXXXXX", e.Value, e.Name)
					}
				}
			}
		})
	}
}

func TestRemoveSecretData(t *testing.T) {
	t.Run("stringData values are redacted", func(t *testing.T) {
		raw := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"default"},"type":"Opaque","stringData":{"token":"supersecret","apiKey":"abc123"}}`
		obj, err := workloadinterface.NewWorkload([]byte(raw))
		assert.NoError(t, err)
		removeData(obj)
		sd, ok := workloadinterface.InspectMap(obj.GetObject(), "stringData")
		assert.True(t, ok, "stringData key must still be present after redaction")
		stringData, ok := sd.(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "XXXXXX", stringData["token"])
		assert.Equal(t, "XXXXXX", stringData["apiKey"])
	})

	t.Run("data and stringData are both redacted", func(t *testing.T) {
		raw := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"default"},"type":"Opaque","data":{"user":"dXNlcg=="},"stringData":{"pass":"cleartext"}}`
		obj, err := workloadinterface.NewWorkload([]byte(raw))
		assert.NoError(t, err)
		removeData(obj)
		d, ok := workloadinterface.InspectMap(obj.GetObject(), "data")
		assert.True(t, ok)
		data, ok := d.(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "XXXXXX", data["user"])
		sd, ok := workloadinterface.InspectMap(obj.GetObject(), "stringData")
		assert.True(t, ok)
		stringData, ok := sd.(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "XXXXXX", stringData["pass"])
	})

	t.Run("absent stringData does not panic", func(t *testing.T) {
		raw := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"default"},"type":"Opaque","data":{"key":"dmFsdWU="}}`
		obj, err := workloadinterface.NewWorkload([]byte(raw))
		assert.NoError(t, err)
		assert.NotPanics(t, func() { removeData(obj) })
		_, ok := workloadinterface.InspectMap(obj.GetObject(), "stringData")
		assert.False(t, ok, "stringData must not appear when it was not present originally")
	})
}

func TestRemoveContainersData(t *testing.T) {
	containers := []corev1.Container{
		{
			Env: []corev1.EnvVar{
				{
					Name:  "TEST_ENV",
					Value: "test_value",
				},
				{
					Name:  "ENV_2",
					Value: "bla",
				},
				{
					Name:  "EMPTY_ENV",
					Value: "",
				},
			},
		},
	}

	removeContainersData(containers)

	for _, c := range containers {
		for _, e := range c.Env {
			assert.Equal(t, "XXXXXX", e.Value)
		}
	}
}

func TestRemoveEphemeralContainersData(t *testing.T) {
	containers := []corev1.EphemeralContainer{
		{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Env: []corev1.EnvVar{
					{
						Name:  "TEST_ENV",
						Value: "test_value",
					},
					{
						Name:  "ENV_2",
						Value: "bla",
					},
					{
						Name:  "EMPTY_ENV",
						Value: "",
					},
				},
			},
		},
	}

	removeEphemeralContainersData(containers)

	for _, c := range containers {
		for _, e := range c.Env {
			assert.Equal(t, "XXXXXX", e.Value)
		}
	}
}

func TestRemoveContainersData_ClearsEnvFrom(t *testing.T) {
	containers := []corev1.Container{
		{
			EnvFrom: []corev1.EnvFromSource{
				{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
					},
				},
				{
					ConfigMapRef: &corev1.ConfigMapEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-configmap"},
					},
				},
			},
		},
	}

	removeContainersData(containers)

	for _, c := range containers {
		assert.Nil(t, c.EnvFrom, "EnvFrom must be cleared to prevent secret name leakage")
	}
}

func TestRemoveEphemeralContainersData_ClearsEnvFrom(t *testing.T) {
	containers := []corev1.EphemeralContainer{
		{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				EnvFrom: []corev1.EnvFromSource{
					{
						SecretRef: &corev1.SecretEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
						},
					},
					{
						ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-configmap"},
						},
					},
				},
			},
		},
	}

	removeEphemeralContainersData(containers)

	for _, c := range containers {
		assert.Nil(t, c.EnvFrom, "EnvFrom must be cleared to prevent secret name leakage")
	}
}

func TestRemoveContainersData_ClearsValueFrom(t *testing.T) {
	containers := []corev1.Container{
		{
			Env: []corev1.EnvVar{
				{
					Name: "SECRET_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
							Key:                  "password",
						},
					},
				},
				{
					Name: "CONFIG_KEY",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-configmap"},
							Key:                  "config-key",
						},
					},
				},
			},
		},
	}
	removeContainersData(containers)
	for _, c := range containers {
		for _, env := range c.Env {
			assert.Nil(t, env.ValueFrom, "ValueFrom must be cleared to prevent secret and configmap name leakage")
		}
	}
}

func TestRemoveEphemeralContainersData_ClearsValueFrom(t *testing.T) {
	containers := []corev1.EphemeralContainer{
		{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Env: []corev1.EnvVar{
					{
						Name: "SECRET_KEY",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
								Key:                  "password",
							},
						},
					},
					{
						Name: "CONFIG_KEY",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "my-configmap"},
								Key:                  "config-key",
							},
						},
					},
				},
			},
		},
	}
	removeEphemeralContainersData(containers)
	for _, c := range containers {
		for _, env := range c.Env {
			assert.Nil(t, env.ValueFrom, "ValueFrom must be cleared to prevent secret and configmap name leakage")
		}
	}
}
func TestApplyExceptionsToManualControls(t *testing.T) {
	processor := exceptions.NewProcessor()

	manualControl := reportsummary.ControlSummary{
		ControlID: "C-0286",
		StatusInfo: apis.StatusInfo{
			InnerStatus: apis.StatusSkipped,
			SubStatus:   apis.SubStatusManualReview,
		},
	}
	nonManualControl := reportsummary.ControlSummary{
		ControlID: "C-0001",
		StatusInfo: apis.StatusInfo{
			InnerStatus: apis.StatusFailed,
		},
	}

	exceptionForManual := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{ControlID: "C-0286"},
		},
	}

	_ = exceptionForManual // kept for reference; cluster-scoped variants used in tests below

	makeSummary := func(controls reportsummary.ControlSummaries) *reportsummary.SummaryDetails {
		return &reportsummary.SummaryDetails{Controls: controls}
	}

	// exceptionForManualWithCluster is scoped to prod-cluster only
	exceptionForManualWithCluster := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{ControlID: "C-0286"},
		},
		Resources: []identifiers.PortalDesignator{
			{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"cluster": "prod-cluster"}},
		},
	}

	// exceptionForManualNoCluster has a resource designator but no cluster constraint
	exceptionForManualNoCluster := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{ControlID: "C-0286"},
		},
		Resources: []identifiers.PortalDesignator{
			{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
		},
	}

	t.Run("no exceptions defined", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, nil, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception matches manual control — no cluster constraint", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualNoCluster}, "any-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception matches manual control — cluster matches", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualWithCluster}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception does not apply — cluster mismatch", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualWithCluster}, "dev-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception cluster uses regex — matches", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		regexException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"cluster": "prod-.*"}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{regexException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception cluster uses regex — no match", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		regexException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"cluster": "prod-.*"}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{regexException}, "dev-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception does not match non-manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0001": nonManualControl})
		// exception explicitly targets C-0001 — the only reason it should be skipped
		// is because the control is not SubStatusManualReview, not because the ID doesn't match
		exceptionForNonManual := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForNonManual}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0001"]
		assert.Equal(t, apis.SubStatusUnknown, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusFailed, ctrl.GetStatus().Status())
	})

	t.Run("exception does not match different control ID", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{
			"C-0287": {
				ControlID:  "C-0287",
				StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview},
			},
		})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualNoCluster}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0287"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("only matching manual control is updated, others unchanged", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{
			"C-0286": manualControl,
			"C-0287": {
				ControlID:  "C-0287",
				StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview},
			},
		})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualNoCluster}, "prod-cluster", processor)
		matched := sd.Controls["C-0286"]
		unmatched := sd.Controls["C-0287"]
		assert.Equal(t, apis.SubStatusException, matched.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, matched.GetStatus().Status())
		assert.Equal(t, apis.SubStatusManualReview, unmatched.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, unmatched.GetStatus().Status())
	})

	t.Run("framework controls are updated in sync with top-level controls", func(t *testing.T) {
		sd := &reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{"C-0286": manualControl},
			Frameworks: []reportsummary.FrameworkSummary{
				{Controls: reportsummary.ControlSummaries{"C-0286": manualControl}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualNoCluster}, "prod-cluster", processor)
		topLevel := sd.Controls["C-0286"]
		fwLevel := sd.Frameworks[0].Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, topLevel.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, topLevel.GetStatus().Status())
		assert.Equal(t, apis.SubStatusException, fwLevel.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, fwLevel.GetStatus().Status())
	})

	t.Run("broad exception with empty posturePolicies does not affect manual controls", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		broadException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{}, // empty = matches all resources, not controls
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{broadException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception with no Resources field matches any cluster", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		noResourcesException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			// no Resources = no scope constraint, applies everywhere
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{noResourcesException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("empty control summaries", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{})
		assert.NotPanics(t, func() {
			applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManualNoCluster}, "prod-cluster", processor)
		})
	})

	t.Run("case-insensitive controlID match", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		lowerCaseException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "c-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{lowerCaseException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception with frameworkName only does not match", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		fwOnlyException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "cis-v1.10.0"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{fwOnlyException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
	})

	t.Run("exception with namespace constraint does not apply to manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		namespaceScopedException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"namespace": "kube-system"}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{namespaceScopedException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception with WLID does not apply to manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		wlidException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorWlid, WLID: "wlid://cluster-prod/namespace-default/deployment-nginx"},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{wlidException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("regex controlID match applies exception", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		regexControlException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-028.*"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{regexControlException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("WildWLID constraint does not apply to manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		wildWlidException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorWildWlid, WildWLID: "wlid://cluster-prod/*/deployment-*"},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{wildWlidException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("multiple policies in one exception — second matches", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		multiPolicyException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{
				{ControlID: "C-0001"}, // does not match
				{ControlID: "C-0286"}, // matches
			},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{multiPolicyException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("multiple exceptions — first no match, second matches", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		noMatch := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		match := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{noMatch, match}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("multiple resources — namespace skipped, cluster matches", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		mixedResourcesException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				// first designator has namespace — should be skipped
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"namespace": "kube-system"}},
				// second designator has only cluster — should match
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"cluster": "prod-cluster"}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{mixedResourcesException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("kind constraint does not apply to manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		kindException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0286"}},
			Resources: []identifiers.PortalDesignator{
				{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"kind": "Deployment"}},
			},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{kindException}, "prod-cluster", processor)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})
}

func TestRequiresResourceMatch(t *testing.T) {
	tests := []struct {
		name       string
		designator identifiers.PortalDesignator
		want       bool
	}{
		{
			name:       "empty designator does not require a resource match",
			designator: identifiers.PortalDesignator{},
			want:       false,
		},
		{
			name: "cluster-only attributes do not require a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeCluster: "prod-cluster"},
			},
			want: false,
		},
		{
			name: "wlid requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorWlid,
				WLID:           "wlid://cluster-prod/namespace-default/deployment-nginx",
			},
			want: true,
		},
		{
			name: "wild wlid requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorWildWlid,
				WildWLID:       "wlid://cluster-prod/*/deployment-*",
			},
			want: true,
		},
		{
			name: "namespace attribute requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeNamespace: "kube-system"},
			},
			want: true,
		},
		{
			name: "name attribute requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeName: "nginx"},
			},
			want: true,
		},
		{
			name: "kind attribute requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeKind: "Deployment"},
			},
			want: true,
		},
		{
			name: "path attribute requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributePath: "/spec/template"},
			},
			want: true,
		},
		{
			name: "resourceID attribute requires a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeResourceID: "resource-123"},
			},
			want: true,
		},
		{
			name: "labels require a resource match",
			designator: identifiers.PortalDesignator{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{"app": "nginx"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, requiresResourceMatch(tt.designator))
		})
	}
}

// mockCounters implements reportsummary.ICounters for testing
type mockCounters struct {
	failed, skipped, passed, excluded int
}

func (m mockCounters) Failed() int   { return m.failed }
func (m mockCounters) Skipped() int  { return m.skipped }
func (m mockCounters) Passed() int   { return m.passed + m.excluded }
func (m mockCounters) Excluded() int { return m.excluded }
func (m mockCounters) All() int      { return m.failed + m.skipped + m.passed + m.excluded }

func TestIsEmptyResources(t *testing.T) {
	tests := []struct {
		name     string
		counters mockCounters
		want     bool
	}{
		{
			name:     "all zero — empty",
			counters: mockCounters{},
			want:     true,
		},
		{
			name:     "one failed — not empty",
			counters: mockCounters{failed: 1},
			want:     false,
		},
		{
			name:     "one passed — not empty",
			counters: mockCounters{passed: 1},
			want:     false,
		},
		{
			name:     "one skipped — not empty",
			counters: mockCounters{skipped: 1},
			want:     false,
		},
		{
			name:     "one excluded — not empty (excluded counts as passed)",
			counters: mockCounters{excluded: 1},
			want:     false,
		},
		{
			name:     "mixed non-zero — not empty",
			counters: mockCounters{failed: 2, passed: 3, skipped: 1},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isEmptyResources(tt.counters))
		})
	}
}

func TestMapControlToInfo(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"resource-with-empty-control": {
			InnerStatus: apis.StatusSkipped,
			InnerInfo:   "external result only",
		},
		"resource-with-k8s-results": {
			InnerStatus: apis.StatusFailed,
			InnerInfo:   "should not override a control with resource counters",
		},
		"resource-with-excluded-results": {
			InnerStatus: apis.StatusPassed,
			InnerInfo:   "excluded resources count as non-empty",
		},
		"resource-with-missing-control": {
			InnerStatus: apis.StatusPassed,
			InnerInfo:   "control is not present in the summary",
		},
		"resource-without-controls": {
			InnerStatus: apis.StatusPassed,
			InnerInfo:   "resource is not mapped to any control",
		},
	}

	got := mapControlToInfo(
		map[string][]string{
			"resource-with-empty-control":    {"C-0001"},
			"resource-with-k8s-results":      {"C-0002"},
			"resource-with-excluded-results": {"C-0003"},
			"resource-with-missing-control":  {"C-9999"},
		},
		infoMap,
		reportsummary.ControlSummaries{
			"C-0001": {
				ControlID: "C-0001",
			},
			"C-0002": {
				ControlID: "C-0002",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 1,
				},
			},
			"C-0003": {
				ControlID: "C-0003",
				StatusCounters: reportsummary.StatusCounters{
					ExcludedResources: 2,
				},
			},
		},
	)

	assert.Equal(t, map[string]apis.StatusInfo{
		"C-0001": infoMap["resource-with-empty-control"],
	}, got)
}

func TestFilterExpiredExceptions(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	makePolicy := func(expiration *time.Time) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			ExpirationDate: expiration,
			PosturePolicies: []armotypes.PosturePolicy{
				{ControlID: "C-0001"},
			},
		}
	}

	tests := []struct {
		name       string
		exceptions []armotypes.PostureExceptionPolicy
		wantLen    int
	}{
		{
			name:       "nil slice is returned as is",
			exceptions: nil,
			wantLen:    0,
		},
		{
			name:       "empty slice is returned as is",
			exceptions: []armotypes.PostureExceptionPolicy{},
			wantLen:    0,
		},
		{
			name: "nil expiration date is kept",
			exceptions: []armotypes.PostureExceptionPolicy{
				makePolicy(nil),
			},
			wantLen: 1,
		},
		{
			name: "future expiration date is kept",
			exceptions: []armotypes.PostureExceptionPolicy{
				makePolicy(&future),
			},
			wantLen: 1,
		},
		{
			name: "past expiration date is filtered out",
			exceptions: []armotypes.PostureExceptionPolicy{
				makePolicy(&past),
			},
			wantLen: 0,
		},
		{
			name: "mixed nil, future, and past — only past is filtered",
			exceptions: []armotypes.PostureExceptionPolicy{
				makePolicy(nil),
				makePolicy(&future),
				makePolicy(&past),
			},
			wantLen: 2,
		},
		{
			name: "all expired are filtered out",
			exceptions: []armotypes.PostureExceptionPolicy{
				makePolicy(&past),
				makePolicy(&past),
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterExpiredExceptions(tt.exceptions)
			assert.Len(t, got, tt.wantLen)

			for _, e := range got {
				if e.ExpirationDate != nil {
					assert.True(t, e.ExpirationDate.After(time.Now()),
						"filtered exceptions must have future ExpirationDate")
				}
			}
		})
	}
}

func makeTestWorkload(t *testing.T, raw string) workloadinterface.IMetadata {
	t.Helper()
	workload, err := workloadinterface.NewWorkload([]byte(raw))
	require.NoError(t, err)
	require.NotNil(t, workload)
	return workload
}

func TestParseControlList(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{"empty string", "", []string{}},
		{"single id", "C-0016", []string{"C-0016"}},
		{"comma separated with spaces", "C-0016, C-0017 , C-0018", []string{"C-0016", "C-0017", "C-0018"}},
		{"extra commas", ",C-0016,,C-0017,", []string{"C-0016", "C-0017"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseControlList(tt.value))
		})
	}
}

func TestInlineExceptionFromResource(t *testing.T) {
	workload := makeTestWorkload(t, `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "nginx",
			"namespace": "default",
			"annotations": {
				"kubescape.io/skip-controls": "C-0016, C-0017",
				"kubescape.io/skip-reason":   "accepted by security team",
				"kubescape.io/skip-expiry":   "2026-12-31T23:59:59Z"
			}
		},
		"spec": {"containers": [{"name": "nginx", "image": "nginx"}]}
	}`)

	got := inlineExceptionFromResource(workload, "test-cluster")
	require.Len(t, got, 1)

	ex := got[0]
	assert.Equal(t, "postureExceptionPolicy", ex.PolicyType)
	assert.Equal(t, "inline-"+workload.GetID(), ex.Name)
	require.Len(t, ex.PosturePolicies, 2)
	assert.Equal(t, "C-0016", ex.PosturePolicies[0].ControlID)
	assert.Equal(t, "C-0017", ex.PosturePolicies[1].ControlID)

	require.NotNil(t, ex.Reason)
	assert.Equal(t, "accepted by security team", *ex.Reason)

	require.NotNil(t, ex.ExpirationDate)
	expected, _ := time.Parse(time.RFC3339, "2026-12-31T23:59:59Z")
	assert.Equal(t, expected.UTC(), ex.ExpirationDate.UTC())

	require.Len(t, ex.Resources, 1)
	attrs := ex.Resources[0].Attributes
	assert.Equal(t, "nginx", attrs["name"])
	assert.Equal(t, "Pod", attrs["kind"])
	assert.Equal(t, "default", attrs["namespace"])
	assert.Equal(t, workload.GetID(), attrs["resourceID"])
}

func TestInlineExceptionFromResource_NoSkipAnnotation(t *testing.T) {
	workload := makeTestWorkload(t, `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "nginx", "namespace": "default"},
		"spec": {"containers": [{"name": "nginx", "image": "nginx"}]}
	}`)

	assert.Empty(t, inlineExceptionFromResource(workload, "test-cluster"))
}

func TestInlineExceptionFromResource_MalformedExpiry(t *testing.T) {
	workload := makeTestWorkload(t, `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "nginx",
			"namespace": "default",
			"annotations": {
				"kubescape.io/skip-controls": "C-0001",
				"kubescape.io/skip-expiry":   "2026-12-31"
			}
		}
	}`)

	assert.Empty(t, inlineExceptionFromResource(workload, "test-cluster"))
}

func TestGatherInlineExceptions(t *testing.T) {
	withSkip := makeTestWorkload(t, `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "nginx",
			"namespace": "default",
			"annotations": {"kubescape.io/skip-controls": "C-0001"}
		}
	}`)
	withoutSkip := makeTestWorkload(t, `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "redis", "namespace": "default"}
	}`)

	opap := &OPAProcessor{
		OPASessionObj: &cautils.OPASessionObj{
			AllResources: map[string]workloadinterface.IMetadata{
				withSkip.GetID():    withSkip,
				withoutSkip.GetID(): withoutSkip,
			},
		},
		clusterName: "test-cluster",
	}

	got := opap.gatherInlineExceptions()
	require.Len(t, got, 1)
	assert.Equal(t, "C-0001", got[0].PosturePolicies[0].ControlID)
}

// Regression for issue-3368: a scope-less exception (no Resources) is documented
// and implemented as "applies everywhere" for manual controls (see
// matchingControlExceptions above and #1994), but the vendored opa-utils
// exceptions.Processor.GetResourceExceptions iterates ruleException.Resources per
// candidate, so an empty Resources list is zero iterations and therefore never a
// match for resource-backed findings. resourceScopedExceptions closes that gap by
// giving each scope-less exception a resource-specific designator right before it
// reaches that matching code.
func TestResourceScopedExceptions(t *testing.T) {
	scoped := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "already-scoped"},
		Resources: []identifiers.PortalDesignator{
			{DesignatorType: identifiers.DesignatorAttributes, Attributes: map[string]string{"namespace": "default"}},
		},
	}
	scopeLess := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "scope-less"},
	}

	t.Run("nil input returned as is", func(t *testing.T) {
		got := resourceScopedExceptions(nil, "res-1")
		assert.Nil(t, got)
	})

	t.Run("all exceptions already scoped are returned unchanged", func(t *testing.T) {
		in := []armotypes.PostureExceptionPolicy{scoped}
		got := resourceScopedExceptions(in, "res-1")
		assert.Equal(t, in, got)
	})

	t.Run("scope-less exception gets a resourceID designator", func(t *testing.T) {
		got := resourceScopedExceptions([]armotypes.PostureExceptionPolicy{scopeLess}, "res-1")
		require.Len(t, got, 1)
		require.Len(t, got[0].Resources, 1)
		assert.Equal(t, identifiers.DesignatorAttributes, got[0].Resources[0].DesignatorType)
		assert.Equal(t, "res-1", got[0].Resources[0].Attributes[identifiers.AttributeResourceID])
		// the original slice element must not be mutated
		assert.Empty(t, scopeLess.Resources)
	})

	t.Run("mixed scoped and scope-less: only the scope-less one is touched", func(t *testing.T) {
		got := resourceScopedExceptions([]armotypes.PostureExceptionPolicy{scoped, scopeLess}, "res-2")
		require.Len(t, got, 2)
		assert.Equal(t, scoped, got[0])
		require.Len(t, got[1].Resources, 1)
		assert.Equal(t, "res-2", got[1].Resources[0].Attributes[identifiers.AttributeResourceID])
	})
}

// End-to-end regression for issue-3368: runs the real updateResults path against a
// resource-backed failing control with a scope-less exception targeting it, and
// checks that the exception actually suppresses the finding - not just that
// resourceScopedExceptions produces the right shape in isolation.
func TestUpdateResults_ScopeLessExceptionSuppressesResourceBackedFinding(t *testing.T) {
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	})

	newFailingResult := func() resourcesresults.Result {
		return resourcesresults.Result{
			ResourceID: resource.GetID(),
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Name:      "control-1",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{Name: "rule-a", Status: apis.StatusFailed},
					},
				},
			},
		}
	}

	newSession := func(result resourcesresults.Result, scopeLessException armotypes.PostureExceptionPolicy) *cautils.OPASessionObj {
		session := cautils.NewOPASessionObjMock()
		session.AllResources[resource.GetID()] = resource
		session.ResourcesResult[resource.GetID()] = result
		session.Exceptions = []armotypes.PostureExceptionPolicy{scopeLessException}
		session.AllPolicies = &cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
			},
		}
		session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001"},
		}
		return session
	}

	t.Run("scope-less exception suppresses the matching resource-backed finding", func(t *testing.T) {
		scopeLessException := armotypes.PostureExceptionPolicy{
			PortalBase: armotypes.PortalBase{Name: "scope-less-exception"},
			PosturePolicies: []armotypes.PosturePolicy{
				{ControlID: "C-0001"},
			},
			// Resources deliberately left empty/nil - this is the documented
			// "applies everywhere" shape from #1994.
		}

		opap := &OPAProcessor{OPASessionObj: newSession(newFailingResult(), scopeLessException)}
		opap.updateResults(context.Background())

		result := opap.ResourcesResult[resource.GetID()]
		require.Len(t, result.AssociatedControls, 1)
		ctrl := result.AssociatedControls[0]
		assert.True(t, ctrl.GetStatus(nil).IsPassed(),
			"a scope-less exception must suppress a resource-backed finding the same way it already does for manual controls")
		assert.Equal(t, apis.SubStatusException, ctrl.GetStatus(nil).GetSubStatus())
	})

	t.Run("scope-less exception for a different control does not suppress this one", func(t *testing.T) {
		unrelatedException := armotypes.PostureExceptionPolicy{
			PortalBase: armotypes.PortalBase{Name: "scope-less-unrelated"},
			PosturePolicies: []armotypes.PosturePolicy{
				{ControlID: "C-9999"},
			},
		}

		opap := &OPAProcessor{OPASessionObj: newSession(newFailingResult(), unrelatedException)}
		opap.updateResults(context.Background())

		result := opap.ResourcesResult[resource.GetID()]
		require.Len(t, result.AssociatedControls, 1)
		assert.True(t, result.AssociatedControls[0].GetStatus(nil).IsFailed(),
			"an exception for an unrelated control must not suppress this finding")
	})
}

func TestBuildControlExcludedRules(t *testing.T) {
	framework := []reporthandling.Framework{{
		Controls: []reporthandling.Control{
			{ControlID: "C-0001", Rules: []reporthandling.PolicyRule{{PortalBase: armotypes.PortalBase{Name: "rule-a"}}}},
			{ControlID: "C-0002", Rules: []reporthandling.PolicyRule{{PortalBase: armotypes.PortalBase{Name: "rule-b"}}}},
			{ControlID: "C-0003", Rules: []reporthandling.PolicyRule{{PortalBase: armotypes.PortalBase{Name: "rule-c"}}}},
		},
	}}

	tests := []struct {
		name          string
		base          map[string]bool
		skip          []string
		include       []string
		excludedRules []string
		notExcluded   []string
	}{
		{
			name:          "no filters",
			base:          map[string]bool{"rule-a": false},
			excludedRules: nil,
			notExcluded:   []string{"rule-a", "rule-b", "rule-c"},
		},
		{
			name:          "skip one control",
			skip:          []string{"C-0002"},
			excludedRules: []string{"rule-b"},
			notExcluded:   []string{"rule-a", "rule-c"},
		},
		{
			name:          "include only two controls",
			include:       []string{"C-0001", "C-0002"},
			excludedRules: []string{"rule-c"},
			notExcluded:   []string{"rule-a", "rule-b"},
		},
		{
			name:          "include two and skip one of them",
			include:       []string{"C-0001", "C-0002"},
			skip:          []string{"C-0002"},
			excludedRules: []string{"rule-b", "rule-c"},
			notExcluded:   []string{"rule-a"},
		},
		{
			name:          "unknown control ids are ignored",
			skip:          []string{"C-9999"},
			excludedRules: nil,
			notExcluded:   []string{"rule-a", "rule-b", "rule-c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildControlExcludedRules(tt.base, framework, tt.skip, tt.include)
			for _, rule := range tt.excludedRules {
				assert.True(t, got[rule], "expected rule %q to be excluded", rule)
			}
			for _, rule := range tt.notExcluded {
				assert.False(t, got[rule], "expected rule %q not to be excluded", rule)
			}
		})
	}
}

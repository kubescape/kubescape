package opaprocessor

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

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
			name: "remove configMap data",
			args: args{
				w: `{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "example-configmap", "namespace": "default", "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}}, "data": {"exampleKey": "exampleValue"}}`,
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
				data, ok := d.(map[string]interface{})
				assert.True(t, ok)
				for key := range data {
					assert.Equal(t, "XXXXXX", data[key])
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
func (m mockCounters) Passed() int   { return m.passed }
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
			name:     "one excluded — empty (excluded does not count as a result)",
			counters: mockCounters{excluded: 1},
			want:     true,
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

func TestIsLargeCluster(t *testing.T) {
	orig := largeClusterSize
	t.Cleanup(func() { largeClusterSize = orig })
	t.Setenv("LARGE_CLUSTER_SIZE", "2500")

	tests := []struct {
		name        string
		clusterSize int
		want        bool
	}{
		{
			name:        "zero nodes — not large",
			clusterSize: 0,
			want:        false,
		},
		{
			name:        "below threshold — not large",
			clusterSize: 100,
			want:        false,
		},
		{
			name:        "at threshold — not large (exclusive)",
			clusterSize: 2500,
			want:        false,
		},
		{
			name:        "above threshold — large",
			clusterSize: 2501,
			want:        true,
		},
		{
			name:        "well above threshold — large",
			clusterSize: 10000,
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			largeClusterSize = -1
			assert.Equal(t, tt.want, isLargeCluster(tt.clusterSize))
		})
	}
}

func TestGetNamespaceName(t *testing.T) {
	orig := largeClusterSize
	t.Cleanup(func() { largeClusterSize = orig })
	t.Setenv("LARGE_CLUSTER_SIZE", "2500")

	podJSON := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"mypod","namespace":"mynamespace"}}`
	namespaceJSON := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"mynamespace"}}`
	nodeJSON := `{"apiVersion":"v1","kind":"Node","metadata":{"name":"mynode"}}`

	pod, err := workloadinterface.NewWorkload([]byte(podJSON))
	require.NoError(t, err)
	require.NotNil(t, pod)

	ns, err := workloadinterface.NewWorkload([]byte(namespaceJSON))
	require.NoError(t, err)
	require.NotNil(t, ns)

	node, err := workloadinterface.NewWorkload([]byte(nodeJSON))
	require.NoError(t, err)
	require.NotNil(t, node)

	tests := []struct {
		name        string
		obj         workloadinterface.IMetadata
		clusterSize int
		want        string
	}{
		{
			name:        "small cluster — always clusterScope",
			obj:         pod,
			clusterSize: 10,
			want:        clusterScope,
		},
		{
			name:        "large cluster — namespaced resource returns namespace",
			obj:         pod,
			clusterSize: 3000,
			want:        "mynamespace",
		},
		{
			name:        "large cluster — Namespace kind returns its name",
			obj:         ns,
			clusterSize: 3000,
			want:        "mynamespace",
		},
		{
			name:        "large cluster — cluster-scoped resource returns clusterScope",
			obj:         node,
			clusterSize: 3000,
			want:        clusterScope,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			largeClusterSize = -1
			assert.Equal(t, tt.want, getNamespaceName(tt.obj, tt.clusterSize))
		})
	}
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

package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
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

func TestApplyExceptionsToManualControls(t *testing.T) {
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

	makeSummary := func(controls reportsummary.ControlSummaries) *reportsummary.SummaryDetails {
		return &reportsummary.SummaryDetails{Controls: controls}
	}

	t.Run("no exceptions defined", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, nil)
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("exception matches manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManual})
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception does not match non-manual control", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0001": nonManualControl})
		// exception explicitly targets C-0001 — the only reason it should be skipped
		// is because the control is not SubStatusManualReview, not because the ID doesn't match
		exceptionForNonManual := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForNonManual})
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
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManual})
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
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManual})
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
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManual})
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
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{broadException})
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status())
	})

	t.Run("empty control summaries", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{})
		assert.NotPanics(t, func() {
			applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{exceptionForManual})
		})
	})

	t.Run("case-insensitive controlID match", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		lowerCaseException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "c-0286"}},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{lowerCaseException})
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusException, ctrl.GetSubStatus())
		assert.Equal(t, apis.StatusPassed, ctrl.GetStatus().Status())
	})

	t.Run("exception with frameworkName only does not match", func(t *testing.T) {
		sd := makeSummary(reportsummary.ControlSummaries{"C-0286": manualControl})
		fwOnlyException := armotypes.PostureExceptionPolicy{
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "cis-v1.10.0"}},
		}
		applyExceptionsToManualControls(sd, []armotypes.PostureExceptionPolicy{fwOnlyException})
		ctrl := sd.Controls["C-0286"]
		assert.Equal(t, apis.SubStatusManualReview, ctrl.GetSubStatus())
	})
}

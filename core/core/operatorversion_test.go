package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func newFakeDeployClient() dynamic.Interface {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		operatorDeploymentGVR: "DeploymentList",
	})
}

func TestCheckOperatorVersionWithClient(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client returns nil", func(t *testing.T) {
		err := CheckOperatorVersionWithClient(ctx, nil, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("deployment version older than min version returns error", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "v0.2.224",
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
		assert.Contains(t, err.Error(), "found v0.2.224 in namespace \"kubescape\"")
	})

	t.Run("deployment version equal to min version passes", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "v0.2.240",
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("deployment version greater than min version passes", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "v0.3.0",
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("deployment discovered by label with old image tag returns error", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "custom-operator-name",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/name": "operator",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.224",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
	})

	t.Run("deployment image tag latest is allowed", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:latest",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("no deployment found is allowed", func(t *testing.T) {
		dyn := newFakeDeployClient()

		err := CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("deployment image tag with digest older than min version returns error", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.224@sha256:738596646849488392",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
	})

	t.Run("deployment image tag with digest equal to min version passes", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.240@sha256:738596646849488392",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("permission forbidden error is propagated", func(t *testing.T) {
		scheme := runtime.NewScheme()
		dynFake := dynamicfake.NewSimpleDynamicClient(scheme)
		dynFake.PrependReactor("get", "deployments", func(action clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "operator", errors.New("forbidden"))
		})

		err := CheckOperatorVersionWithClient(ctx, dynFake, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checking operator deployment in namespace \"kubescape\"")
	})

	t.Run("image tag preferred over chart version label on old image", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "1.42.0",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.224",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
		assert.Contains(t, err.Error(), "found v0.2.224 in namespace \"kubescape\"")
	})

	t.Run("image tag preferred over chart version label on newer image", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "0.1.0",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.245",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("development tag latest preferred over chart version label", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "0.1.0",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:latest",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("explicitly named operator container preferred over sidecar with operator in image", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "metrics",
									"image": "example/operator-metrics:v0.3.0",
								},
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator:v0.2.224",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
		assert.Contains(t, err.Error(), "found v0.2.224 in namespace \"kubescape\"")
	})

	t.Run("renamed operator container discovered by image when container named operator is absent", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "custom-main",
									"image": "quay.io/kubescape/operator:v0.2.240",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("digest-only image with registry port falls back to version label", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "v0.2.224",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "registry.example:5000/operator@sha256:738596646849488392",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
		assert.Contains(t, err.Error(), "found v0.2.224 in namespace \"kubescape\"")
	})

	t.Run("image with registry port and explicit tag extracts tag correctly", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "0.1.0",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "operator",
									"image": "registry.example:5000/kubescape/operator:v0.2.240@sha256:738596646849488392",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.NoError(t, err)
	})

	t.Run("digest-only operator container with sidecar falls back to version label instead of sidecar tag", func(t *testing.T) {
		dyn := newFakeDeployClient()

		deploy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name":      "operator",
					"namespace": "kubescape",
					"labels": map[string]interface{}{
						"app.kubernetes.io/version": "v0.2.224",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "metrics",
									"image": "example/operator-metrics:v0.3.0",
								},
								map[string]interface{}{
									"name":  "operator",
									"image": "quay.io/kubescape/operator@sha256:738596646849488392",
								},
							},
						},
					},
				},
			},
		}
		_, err := dyn.Resource(operatorDeploymentGVR).Namespace("kubescape").Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err)

		err = CheckOperatorVersionWithClient(ctx, dyn, "kubescape", "v0.2.240")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operator remediate patch requires Kubescape Operator >= v0.2.240")
		assert.Contains(t, err.Error(), "found v0.2.224 in namespace \"kubescape\"")
	})
}

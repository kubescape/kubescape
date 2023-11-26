package hostsensorutils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHostSensorHandler(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("with default manifest", func(t *testing.T) {
		t.Run("should build host sensor", func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()), WithPod(mockPod1()), WithPod(mockPod2()), WithResponses(mockResponses()))
			h, err := NewHostSensorHandler(k8s, "")
			require.NoError(t, err)
			require.NotNil(t, h)

			t.Run("should initialize host sensor", func(t *testing.T) {
				require.NoError(t, h.Init(ctx))

				w, err := k8s.KubernetesClient.CoreV1().Pods(h.daemonSet.Namespace).Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				w.Stop()

				require.Len(t, h.hostSensorPodNames, 2)
			})

			t.Run("should return namespace", func(t *testing.T) {
				require.Equal(t, "kubescape", h.GetNamespace())
			})

			t.Run("should collect resources from pods - happy path", func(t *testing.T) {
				envelope, status, err := h.CollectResources(ctx)
				require.NoError(t, err)

				require.Len(t, envelope, 9*2) // has cloud provider, no control plane requested
				require.Len(t, status, 0)

				foundControl, foundProvider := false, false
				for _, sensed := range envelope {
					if sensed.Kind == ControlPlaneInfo.String() {
						foundControl = true
					}
					if sensed.Kind == CloudProviderInfo.String() {
						foundProvider = hasCloudProviderInfo([]hostsensor.HostSensorDataEnvelope{sensed})
					}
				}

				require.False(t, foundControl)
				require.True(t, foundProvider)
			})
		})

		t.Run("should build host sensor without cloud provider", func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()), WithPod(mockPod1()), WithPod(mockPod2()), WithResponses(mockResponsesNoCloudProvider()))
			h, err := NewHostSensorHandler(k8s, "")
			require.NoError(t, err)
			require.NotNil(t, h)

			t.Run("should initialize host sensor", func(t *testing.T) {
				require.NoError(t, h.Init(ctx))

				w, err := k8s.KubernetesClient.CoreV1().Pods(h.daemonSet.Namespace).Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				w.Stop()

				require.Len(t, h.hostSensorPodNames, 2)
			})

			t.Run("should get version", func(t *testing.T) {
				version, err := h.getVersion()
				require.NoError(t, err)
				require.Equal(t, "v1.0.45", version)
			})

			t.Run("ForwardToPod is a stub, not implemented", func(t *testing.T) {
				resp, err := h.forwardToPod("pod1", "/version")
				require.Contains(t, err.Error(), "not implemented")
				require.Nil(t, resp)
			})

			t.Run("should collect resources from pods", func(t *testing.T) {
				envelope, status, err := h.CollectResources(ctx)
				require.NoError(t, err)

				require.Len(t, envelope, 10*2) // has empty cloud provider, has control plane info
				require.Len(t, status, 0)

				foundControl, foundProvider := false, false
				for _, sensed := range envelope {
					if sensed.Kind == ControlPlaneInfo.String() {
						foundControl = true
					}
					if sensed.Kind == CloudProviderInfo.String() {
						foundProvider = hasCloudProviderInfo([]hostsensor.HostSensorDataEnvelope{sensed})
					}
				}

				require.True(t, foundControl)
				require.False(t, foundProvider)
			})
		})

		t.Run("should build host sensor with error in response from /version", func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()),
				WithPod(mockPod1()),
				WithPod(mockPod2()),
				WithResponses(mockResponsesNoCloudProvider()),
				WithErrorResponse(RestURL{"http", "pod1", "7888", "/version"}), // this endpoint will return an error from this pod
				WithErrorResponse(RestURL{"http", "pod2", "7888", "/version"}), // this endpoint will return an error from this pod
			)

			h, err := NewHostSensorHandler(k8s, "")
			require.NoError(t, err)
			require.NotNil(t, h)

			t.Run("should initialize host sensor", func(t *testing.T) {
				require.NoError(t, h.Init(ctx))

				w, err := k8s.KubernetesClient.CoreV1().Pods(h.daemonSet.Namespace).Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				w.Stop()

				require.Len(t, h.hostSensorPodNames, 2)
			})

			t.Run("should NOT be able to get version", func(t *testing.T) {
				// NOTE: GetVersion might be successful if only one pod responds successfully.
				// In order to ensure an error, we need ALL pods to error.
				_, err := h.getVersion()
				require.Error(t, err)
				require.Contains(t, err.Error(), "mock")
			})
		})

		t.Run("should FAIL to build host sensor because there are no nodes", func(t *testing.T) {
			h, err := NewHostSensorHandler(NewKubernetesApiMock(), "")
			require.Error(t, err)
			require.NotNil(t, h)
			require.Contains(t, err.Error(), "no nodes to scan")
		})
	})

	t.Run("should NOT build host sensor with nil k8s API", func(t *testing.T) {
		h, err := NewHostSensorHandler(nil, "")
		require.Error(t, err)
		require.Nil(t, h)
	})

	t.Run("with manifest from YAML file", func(t *testing.T) {
		t.Run("should build host sensor", func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()), WithPod(mockPod1()), WithPod(mockPod2()), WithResponses(mockResponses()))
			h, err := NewHostSensorHandler(k8s, filepath.Join(testutils.CurrentDir(), "hostsensor.yaml"))
			require.NoError(t, err)
			require.NotNil(t, h)

			t.Run("should initialize host sensor", func(t *testing.T) {
				require.NoError(t, h.Init(ctx))

				w, err := k8s.KubernetesClient.CoreV1().Pods(h.daemonSet.Namespace).Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				w.Stop()

				require.Len(t, h.hostSensorPodNames, 2)
			})
		})
	})

	t.Run("with manifest from invalid YAML file", func(t *testing.T) {
		t.Run("should NOT build host sensor", func(t *testing.T) {
			var invalid string
			t.Run("should create temp file", func(t *testing.T) {
				file, err := os.CreateTemp("", "*.yaml")
				require.NoError(t, err)
				t.Cleanup(func() {
					_ = os.Remove(file.Name())
				})
				_, err = file.Write([]byte("	x: 1"))
				require.NoError(t, err)

				invalid = file.Name()
				require.NoError(t, file.Close())
			})

			k8s := NewKubernetesApiMock(WithNode(mockNode1()), WithPod(mockPod1()), WithPod(mockPod2()), WithResponses(mockResponses()))
			_, err := NewHostSensorHandler(k8s, filepath.Join(testutils.CurrentDir(), invalid))
			require.Error(t, err)
		})
	})

	// TODO(test coverage): the following cases are not covered by tests yet.
	//
	// * applyYAML fails
	// * checkPodForEachNode fails, or times out
	// * non-active namespace
	// * getPodList fails when GetVersion
	// * getPodList fails when CollectResources
	// * error cases that trigger a namespace tear-down
	// * watch pods with a Delete event
	// * explicit TearDown()
	//
	// Notice that the package doesn't current pass tests with the race detector enabled.
}

func TestLoadHostSensorFromFile_NoError(t *testing.T) {
	content, err := loadHostSensorFromFile("testdata/hostsensor.yaml")
	assert.NotEqual(t, "", content)
	assert.Nil(t, err)
}

func TestLoadHostSensorFromFile_Error(t *testing.T) {
	content, err := loadHostSensorFromFile("testdata/hostsensor_invalid.yaml")
	assert.Equal(t, "", content)
	assert.NotNil(t, err)

	content, err = loadHostSensorFromFile("testdata/empty_hostsensor.yaml")
	assert.Equal(t, "", content)
	assert.NotNil(t, err)

	content, err = loadHostSensorFromFile("testdata/notAYamlFile.txt")
	assert.Equal(t, "", content)
	assert.NotNil(t, err)
}

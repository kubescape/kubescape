package hostsensorutils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v2/internal/testutils"
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
				require.Equal(t, "kubescape-host-scanner", h.GetNamespace())
			})

			t.Run("should collect resources from pods - happy path", func(t *testing.T) {
				envelope, status, err := h.CollectResources(ctx)
				require.NoError(t, err)

				require.Len(t, envelope, 10*2) // has cloud provider, no control plane requested
				require.Len(t, status, 0)

				foundControl, foundProvider := false, false
				for _, sensed := range envelope {
					if sensed.Kind == ControlPlaneInfo.String() {
						foundControl = true
					}
					if sensed.Kind == CloudProviderInfo.String() {
						foundProvider = hasCloudProviderInfo(sensed)
					}
				}

				require.False(t, foundControl)
				require.True(t, foundProvider)

				t.Run("envelope should contain expected content", func(t *testing.T) {
					for _, data := range envelope {
						require.NotEmpty(t, data.GetApiVersion())
						require.NotEmpty(t, data.GetName())
						payload := data.GetData()
						require.NotEmpty(t, payload)

						switch data.Kind {
						case OsReleaseFile.String():
							assert.True(t, bytes.HasPrefix(payload, []byte("NAME=")))
						case KernelVersion.String():
							assert.True(t, bytes.HasPrefix(payload, []byte("Linux version"))) // mock captured on Linux host
						case LinuxSecurityHardeningStatus.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "appArmor")
							assert.Contains(t, fromJSON, "seLinux")
						case CloudProviderInfo.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "providerID")
							assert.NotEmpty(t, fromJSON["providerID"])
						case OpenPortsList.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "tcpPorts")
						case KubeletCommandLine.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "fullCommand")
						case KubeletInfo.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "serviceFiles")
						case KubeProxyInfo.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "cmdLine")
						case CNIInfo.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "CNIConfigFiles")
						case KubeletConfiguration.String():
							var fromJSON map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							assert.Contains(t, fromJSON, "apiVersion")
						case LinuxKernelVariables.String():
							var fromJSON []map[string]interface{}
							require.NoError(t, json.Unmarshal(payload, &fromJSON))
							require.Greater(t, len(fromJSON), 0)

						default:
							t.Errorf("unexpected kind: %s", data.Kind)
						}
					}
				})
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

			t.Run("forwardToPod is a stub, not implemented", func(t *testing.T) {
				resp, err := h.forwardToPod("pod1", "/version")
				require.Contains(t, err.Error(), "not implemented")
				require.Nil(t, resp)
			})

			t.Run("should collect resources from pods", func(t *testing.T) {
				envelope, status, err := h.CollectResources(ctx)
				require.NoError(t, err)

				t.Run("should get version", func(t *testing.T) {
					version := h.getVersion()
					require.Equal(t, "v1.0.45", version)
				})

				require.Len(t, envelope, 11*2) // has empty cloud provider, has control plane info
				require.Len(t, status, 0)

				foundControl, foundProvider := false, false
				for _, sensed := range envelope {
					if sensed.Kind == ControlPlaneInfo.String() {
						foundControl = true
					}
					if sensed.Kind == CloudProviderInfo.String() {
						foundProvider = hasCloudProviderInfo(sensed)
					}
				}

				require.True(t, foundControl)
				require.False(t, foundProvider)
			})
		})

		t.Run(fmt.Sprintf("should build host sensor with error in response from %s", Version.Path()), func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()),
				WithPod(mockPod1()),
				WithPod(mockPod2()),
				WithResponses(mockResponsesNoCloudProvider()),
				WithErrorResponse(RestURL{"http", "pod1", "7888", Version.Path()}), // this endpoint will return an error from this pod
				WithErrorResponse(RestURL{"http", "pod2", "7888", Version.Path()}), // this endpoint will return an error from this pod
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
				version := h.getVersion()
				require.Empty(t, version)
			})
		})

		t.Run(fmt.Sprintf("should build host sensor with error in response from %s", KubeletConfiguration.Path()), func(t *testing.T) {
			k8s := NewKubernetesApiMock(WithNode(mockNode1()),
				WithPod(mockPod1()),
				WithPod(mockPod2()),
				WithResponses(mockResponsesNoCloudProvider()),
				WithErrorResponse(RestURL{"http", "pod1", "7888", KubeletConfiguration.Path()}), // this endpoint will return an error from this pod
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

			t.Run("should collect resources from pods, with some errors", func(t *testing.T) {
				envelope, status, err := h.CollectResources(ctx)
				require.NoError(t, err)

				require.Len(t, envelope, 12*2-1) // one resource is missing
				require.Len(t, status, 1)        // error is now reported in status
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
	// Notice that the package now passes tests with the race detector enabled.
}

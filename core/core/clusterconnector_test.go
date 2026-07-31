package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func readyPod(name string) v1.Pod {
	return v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": "operator"},
		},
		Status: v1.PodStatus{
			Phase:      v1.PodRunning,
			Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionTrue}},
		},
	}
}

func notReadyPod(name string) v1.Pod {
	return v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": "operator"},
		},
		Status: v1.PodStatus{
			Phase:      v1.PodRunning,
			Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionFalse}},
		},
	}
}

func Test_isPodReady(t *testing.T) {
	terminating := readyPod("terminating")
	deletionTimestamp := metav1.NewTime(time.Unix(0, 0))
	terminating.DeletionTimestamp = &deletionTimestamp

	testCases := []struct {
		name string
		pod  v1.Pod
		want bool
	}{
		{
			name: "running and ready",
			pod:  readyPod("p"),
			want: true,
		},
		{
			name: "running but ready condition is false",
			pod:  notReadyPod("p"),
			want: false,
		},
		{
			name: "running with no ready condition at all",
			pod:  v1.Pod{Status: v1.PodStatus{Phase: v1.PodRunning}},
			want: false,
		},
		{
			name: "pending with ready condition true",
			pod: v1.Pod{Status: v1.PodStatus{
				Phase:      v1.PodPending,
				Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionTrue}},
			}},
			want: false,
		},
		{
			name: "terminating pod stays running and ready but must not be selected",
			pod:  terminating,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isPodReady(&tc.pod))
		})
	}
}

func Test_getOperatorPod(t *testing.T) {
	notReadyErr := func(count int) error {
		return fmt.Errorf("found %d Kubescape Operator pod(s) in namespace %q, but none are running and ready", count, kubescapeNamespace)
	}

	testCases := []struct {
		name         string
		pods         []v1.Pod
		expectedErr  error
		expectedName string
	}{
		{
			name:        "no operator pod exists",
			pods:        nil,
			expectedErr: errOperatorNotFound,
		},
		{
			name:         "single ready pod is returned",
			pods:         []v1.Pod{readyPod("first")},
			expectedName: "first",
		},
		{
			name:        "single not-ready pod is reported, not handed to the caller",
			pods:        []v1.Pod{notReadyPod("first")},
			expectedErr: notReadyErr(1),
		},
		{
			name:         "multiple pods, the ready one is selected even when it sorts after the not-ready one",
			pods:         []v1.Pod{notReadyPod("aaa-not-ready"), readyPod("zzz-ready")},
			expectedName: "zzz-ready",
		},
		{
			name:        "multiple pods, none ready",
			pods:        []v1.Pod{notReadyPod("first"), notReadyPod("second")},
			expectedErr: notReadyErr(2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewClientset(),
				Context:          context.Background(),
			}

			for i := range tc.pods {
				_, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &tc.pods[i], metav1.CreateOptions{})
				assert.NoError(t, err)
			}

			pod, err := getOperatorPod(&k8sClient, kubescapeNamespace)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedName, pod.Name)
		})
	}
}

func Test_getOperatorPod_nilClient(t *testing.T) {
	_, err := getOperatorPod(nil, kubescapeNamespace)
	assert.EqualError(t, err, "kubernetes client is not initialised")

	_, err = getOperatorPod(&k8sinterface.KubernetesApi{}, kubescapeNamespace)
	assert.EqualError(t, err, "kubernetes client is not initialised")
}

func TestNewOperatorAdapter_NotConnectedToCluster(t *testing.T) {
	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(false)

	adapter, err := NewOperatorAdapter(&fakeOperatorScanInfo{}, kubescapeNamespace)

	assert.Nil(t, adapter)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not connect to cluster")
}

// fakeOperatorScanInfo and fakeOperatorConnector let httpPostOperatorScanRequest
// and OperatorScan be driven directly, without a real cluster/port-forward.
type fakeOperatorScanInfo struct {
	payload       *apis.Commands
	validateErr   error
	validateCalls int
}

func (f *fakeOperatorScanInfo) GetRequestPayload() *apis.Commands {
	if f.payload != nil {
		return f.payload
	}
	return &apis.Commands{Commands: []apis.Command{{CommandName: "scan"}}}
}

func (f *fakeOperatorScanInfo) ValidatePayload(*apis.Commands) error {
	f.validateCalls++
	return f.validateErr
}

type fakeOperatorConnector struct {
	startErr   error
	startCalls int
	stopCalls  int
	localhost  string
}

func (f *fakeOperatorConnector) StartPortForwarder() error {
	f.startCalls++
	return f.startErr
}

func (f *fakeOperatorConnector) StopPortForwarder() {
	f.stopCalls++
}

func (f *fakeOperatorConnector) GetPortForwardLocalhost() string {
	if f.localhost != "" {
		return f.localhost
	}
	return "127.0.0.1:4002"
}

func fakeHTTPPost(statusCode int, postErr error) func(httputils.IHttpClient, string, map[string]string, []byte) (*http.Response, error) {
	return func(httputils.IHttpClient, string, map[string]string, []byte) (*http.Response, error) {
		if postErr != nil {
			return nil, postErr
		}
		return &http.Response{
			StatusCode: statusCode,
			Body:       http.NoBody,
		}, nil
	}
}

func TestOperatorAdapter_httpPostOperatorScanRequest(t *testing.T) {
	testCases := []struct {
		name        string
		startErr    error
		statusCode  int
		postErr     error
		expectErr   string
		expectValue string
	}{
		{
			name:        "success",
			statusCode:  http.StatusOK,
			expectValue: "success",
		},
		{
			name:      "port forwarder fails to start",
			startErr:  errors.New("boom"),
			expectErr: "boom",
		},
		{
			name:      "http post fails",
			postErr:   errors.New("network unreachable"),
			expectErr: "network unreachable",
		},
		{
			name:       "non-200 status",
			statusCode: http.StatusInternalServerError,
			expectErr:  "http-error: 500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			connector := &fakeOperatorConnector{startErr: tc.startErr}
			adapter := &OperatorAdapter{
				httpPostFunc:      fakeHTTPPost(tc.statusCode, tc.postErr),
				OperatorScanInfo:  &fakeOperatorScanInfo{},
				OperatorConnector: connector,
			}

			got, err := adapter.httpPostOperatorScanRequest(apis.Commands{})

			if tc.expectErr != "" {
				require.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), tc.expectErr), "error %q should contain %q", err.Error(), tc.expectErr)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectValue, got)
			}

			// StopPortForwarder must run even on failure paths that reach past StartPortForwarder.
			if tc.startErr == nil {
				assert.Equal(t, 1, connector.stopCalls, "StopPortForwarder must be called after a successful StartPortForwarder")
			} else {
				assert.Equal(t, 0, connector.stopCalls, "StopPortForwarder must not run if StartPortForwarder itself failed")
			}
		})
	}
}

func TestOperatorAdapter_OperatorScan(t *testing.T) {
	t.Run("invalid payload short-circuits before any network call", func(t *testing.T) {
		connector := &fakeOperatorConnector{}
		scanInfo := &fakeOperatorScanInfo{validateErr: errors.New("missing target namespace")}
		adapter := &OperatorAdapter{
			httpPostFunc:      fakeHTTPPost(http.StatusOK, nil),
			OperatorScanInfo:  scanInfo,
			OperatorConnector: connector,
		}

		got, err := adapter.OperatorScan()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing target namespace")
		assert.Empty(t, got)
		assert.Equal(t, 1, scanInfo.validateCalls)
		assert.Equal(t, 0, connector.startCalls, "must not attempt a port-forward when the payload is invalid")
	})

	t.Run("valid payload triggers the scan request", func(t *testing.T) {
		connector := &fakeOperatorConnector{}
		scanInfo := &fakeOperatorScanInfo{}
		adapter := &OperatorAdapter{
			httpPostFunc:      fakeHTTPPost(http.StatusOK, nil),
			OperatorScanInfo:  scanInfo,
			OperatorConnector: connector,
		}

		got, err := adapter.OperatorScan()

		require.NoError(t, err)
		assert.Equal(t, "success", got)
		assert.Equal(t, 1, connector.startCalls)
	})
}

var _ cautils.OperatorScanInfo = (*fakeOperatorScanInfo)(nil)
var _ cautils.OperatorConnector = (*fakeOperatorConnector)(nil)

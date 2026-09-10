package cautils

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// TestWaitForPortForwardReadiness_TimesOutInsteadOfHangingForever reproduces
// the hang: a port-forward whose dial never closes readyChan and never sends
// on errChan (e.g. the peer accepted the connection but never completed the
// SPDY upgrade). Before the readyTimeout case existed, this blocked forever.
func TestWaitForPortForwardReadiness_TimesOutInsteadOfHangingForever(t *testing.T) {
	p := &portForward{
		readyChan:    make(chan struct{}),
		errChan:      make(chan error),
		readyTimeout: 50 * time.Millisecond,
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	// The watchdog is a much longer, generous bound (matching
	// TestStopPortForwarder_Idempotent's pattern): if the fix regresses to an
	// unbounded select, this fails the test instead of hanging the suite.
	select {
	case err := <-done:
		elapsed := time.Since(start)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
		assert.Contains(t, err.Error(), PortForwardReadyTimeoutEnv)
		assert.Less(t, elapsed, 2*time.Second, "should return close to readyTimeout, not after it")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness hung past its readyTimeout")
	}
}

// TestWaitForPortForwardReadiness_ReadyBeforeTimeout is the happy-path
// regression check: the new timer must not delay or interfere with an
// ordinary successful readiness signal.
func TestWaitForPortForwardReadiness_ReadyBeforeTimeout(t *testing.T) {
	readyChan := make(chan struct{})
	p := &portForward{
		readyChan:    readyChan,
		errChan:      make(chan error, 1),
		readyTimeout: 5 * time.Second,
	}
	close(readyChan)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.Less(t, time.Since(start), 1*time.Second, "an already-ready forwarder must not wait on the timer")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness did not return for an already-ready forwarder")
	}
}

// TestWaitForPortForwardReadiness_ErrorBeforeTimeout: a fast ForwardPorts
// failure must still be reported as that failure, not masked by the timer.
func TestWaitForPortForwardReadiness_ErrorBeforeTimeout(t *testing.T) {
	errChan := make(chan error, 1)
	wantErr := assert.AnError
	errChan <- wantErr

	p := &portForward{
		readyChan:    make(chan struct{}),
		errChan:      errChan,
		readyTimeout: 5 * time.Second,
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, wantErr)
		assert.Less(t, time.Since(start), 1*time.Second, "a fast ForwardPorts error must not wait on the timer")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness did not return for a fast ForwardPorts error")
	}
}

func Test_getPortForwardReadyTimeout(t *testing.T) {
	testCases := []struct {
		name     string
		envValue string
		setEnv   bool
		want     time.Duration
	}{
		{
			name: "unset falls back to default",
			want: defaultPortForwardReadyTimeout,
		},
		{
			name:     "valid override is honored",
			setEnv:   true,
			envValue: "5",
			want:     5 * time.Second,
		},
		{
			name:     "zero falls back to default rather than firing instantly",
			setEnv:   true,
			envValue: "0",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "negative falls back to default",
			setEnv:   true,
			envValue: "-5",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "non-numeric falls back to default",
			setEnv:   true,
			envValue: "soon",
			want:     defaultPortForwardReadyTimeout,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(PortForwardReadyTimeoutEnv, tc.envValue)
			}
			assert.Equal(t, tc.want, getPortForwardReadyTimeout())
		})
	}
}

// TestCreatePortForwarder_ResolvesReadyTimeoutFromEnvOnce checks the
// forwarder actually carries the resolved timeout (not just that the helper
// function computes it correctly), and that, like localPort, it is captured
// once at construction rather than re-read later.
func TestCreatePortForwarder_ResolvesReadyTimeoutFromEnvOnce(t *testing.T) {
	t.Setenv(PortForwardReadyTimeoutEnv, "7")

	k8sClient := k8sinterface.KubernetesApi{
		KubernetesClient: fake.NewClientset(),
		K8SConfig: &rest.Config{
			Host: "any",
		},
		Context: context.Background(),
	}

	operatorPod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first",
			Labels: map[string]string{
				"app": "operator",
			},
		},
	}
	createdPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
	require.NoError(t, err)

	connector, err := CreatePortForwarder(&k8sClient, createdPod, "1234", "any")
	require.NoError(t, err)

	pf, ok := connector.(*portForward)
	require.True(t, ok)
	assert.Equal(t, 7*time.Second, pf.readyTimeout)

	// Mutating the environment after construction must not change the
	// already-resolved timeout, matching GetPortForwardLocalhost's existing
	// "resolved once" guarantee for localPort.
	t.Setenv(PortForwardReadyTimeoutEnv, "1")
	assert.Equal(t, 7*time.Second, pf.readyTimeout)
}

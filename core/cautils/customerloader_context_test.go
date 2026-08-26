package cautils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The generated fake clientset discards the context before reactors run
// (see client-go gentype.FakeClient), so context propagation can only be
// asserted at the REST transport layer, where client-go turns the context
// into http.Request.Context().
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func jsonResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    req,
	}
}

// newTestClusterConfig builds a ClusterConfig backed by a clientset whose
// transport is rt, bypassing NewClusterConfig so the test does not touch the
// on-disk config file or the global cloud API connector.
func newTestClusterConfig(t *testing.T, rt http.RoundTripper) *ClusterConfig {
	t.Helper()

	clientset, err := kubernetes.NewForConfig(&rest.Config{
		Host:      "https://kubernetes.test:6443",
		Transport: rt,
	})
	require.NoError(t, err)

	return &ClusterConfig{
		k8s:                &k8sinterface.KubernetesApi{KubernetesClient: clientset},
		configObj:          &ConfigObj{},
		configMapNamespace: kubescapeNamespace,
	}
}

func TestUpdateConfigEmptyFieldsFromKubescapeConfigMap_PropagatesContextValues(t *testing.T) {
	type ctxKey struct{}
	const sentinel = "ctx-sentinel"

	var capturedCtx context.Context
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		capturedCtx = req.Context()
		return jsonResponse(req, `{"apiVersion":"v1","kind":"ConfigMapList","items":[]}`), nil
	})

	c := newTestClusterConfig(t, rt)

	ctx := context.WithValue(context.Background(), ctxKey{}, sentinel)
	require.NoError(t, c.updateConfigEmptyFieldsFromKubescapeConfigMap(ctx))

	require.NotNil(t, capturedCtx, "no request reached the transport")
	assert.Equal(t, sentinel, capturedCtx.Value(ctxKey{}),
		"caller context was not propagated to the Kubernetes API call")
}

func TestUpdateConfigEmptyFieldsFromCredentialsSecret_PropagatesContextValues(t *testing.T) {
	type ctxKey struct{}
	const sentinel = "ctx-sentinel"

	var capturedCtx context.Context
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		capturedCtx = req.Context()
		return jsonResponse(req, `{"apiVersion":"v1","kind":"SecretList","items":[]}`), nil
	})

	c := newTestClusterConfig(t, rt)

	ctx := context.WithValue(context.Background(), ctxKey{}, sentinel)
	require.NoError(t, c.updateConfigEmptyFieldsFromCredentialsSecret(ctx))

	require.NotNil(t, capturedCtx, "no request reached the transport")
	assert.Equal(t, sentinel, capturedCtx.Value(ctxKey{}),
		"caller context was not propagated to the Kubernetes API call")
}

func TestUpdateConfigEmptyFields_ContextCancellationUnblocksSlowAPIServer(t *testing.T) {
	// Simulates an unreachable API server: the request hangs until the caller's
	// context is cancelled. With context.Background() this never returns.
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	testCases := []struct {
		name string
		call func(*ClusterConfig, context.Context) error
	}{
		{
			name: "configmap lookup",
			call: (*ClusterConfig).updateConfigEmptyFieldsFromKubescapeConfigMap,
		},
		{
			name: "credentials secret lookup",
			call: (*ClusterConfig).updateConfigEmptyFieldsFromCredentialsSecret,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClusterConfig(t, rt)

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()
			defer cancel()

			done := make(chan error, 1)
			go func() { done <- tc.call(c, ctx) }()

			select {
			case err := <-done:
				require.Error(t, err, "expected the cancelled request to fail")
				assert.True(t,
					errors.Is(err, context.Canceled) || strings.Contains(err.Error(), context.Canceled.Error()),
					"expected a context.Canceled error, got: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("call did not return after context cancellation - context is not propagated")
			}
		})
	}
}

func TestUpdateConfigEmptyFields_ContextTimeoutIsRespected(t *testing.T) {
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	c := newTestClusterConfig(t, rt)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.updateConfigEmptyFieldsFromKubescapeConfigMap(ctx)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second,
		"deadline from the caller's context was not honoured")
}

// Regression guard: threading the context through must not change how the
// ConfigMap payload is applied to the config object.
func TestUpdateConfigEmptyFieldsFromKubescapeConfigMap_LoadsClusterData(t *testing.T) {
	const body = `{
	  "apiVersion": "v1",
	  "kind": "ConfigMapList",
	  "items": [
	    {
	      "metadata": {"name": "ks-cloud-config", "namespace": "kubescape"},
	      "data": {"clusterData": "{\"accountID\":\"acc-123\",\"cloudAPIURL\":\"https://api.example.com\"}"}
	    }
	  ]
	}`

	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(req, body), nil
	})

	c := newTestClusterConfig(t, rt)

	require.NoError(t, c.updateConfigEmptyFieldsFromKubescapeConfigMap(context.Background()))
	assert.Equal(t, "acc-123", c.configObj.AccountID)
	assert.Equal(t, "https://api.example.com", c.configObj.CloudAPIURL)
}

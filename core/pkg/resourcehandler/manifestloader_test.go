package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/require"
)

const samplePodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx:latest
`

const sampleMultiDocYAML = `apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: default
spec:
  ports:
  - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: web
        image: nginx
`

func TestManifestResourceHandler_ValidYAML(t *testing.T) {
	h := NewManifestResourceHandler([]byte(samplePodYAML))
	session := cautils.NewOPASessionObjMock()
	scanInfo := &cautils.ScanInfo{}

	k8sRes, allRes, extRes, excludedRules, err := h.GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Empty(t, extRes)
	require.NotNil(t, excludedRules)
	require.Len(t, allRes, 1)
	require.NotEmpty(t, session.ResourceSource)

	// Stream resources batch
	batchChan, errChan, _, err := h.StreamResourcesBatches(context.Background(), session, scanInfo)
	require.NoError(t, err)
	batch := <-batchChan
	require.NotNil(t, batch)
	require.Len(t, batch.AllResources, 1)
	require.NoError(t, <-errChan)

	require.Equal(t, "", h.GetCloudProvider())
	require.Nil(t, h.GetClusterAPIServerInfo(context.Background()))
	sz, err := h.EstimateClusterSize(context.Background(), scanInfo)
	require.NoError(t, err)
	require.Equal(t, 0, sz)
	pref, err := h.Preflight(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.NotNil(t, pref)
	_ = k8sRes
}

func TestManifestResourceHandler_MultiDoc(t *testing.T) {
	h := NewManifestResourceHandler([]byte(sampleMultiDocYAML))
	session := cautils.NewOPASessionObjMock()
	scanInfo := &cautils.ScanInfo{}

	_, allRes, _, _, err := h.GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allRes, 2)
}

func TestManifestResourceHandler_Empty(t *testing.T) {
	h := NewManifestResourceHandler([]byte(""))
	session := cautils.NewOPASessionObjMock()
	scanInfo := &cautils.ScanInfo{}

	_, _, _, _, err := h.GetResources(context.Background(), session, scanInfo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing manifest input")
}

func TestManifestResourceHandler_NonKubernetesYAML(t *testing.T) {
	h := NewManifestResourceHandler([]byte("foo: bar\nbaz: 123\n"))
	session := cautils.NewOPASessionObjMock()
	scanInfo := &cautils.ScanInfo{}

	_, _, _, _, err := h.GetResources(context.Background(), session, scanInfo)
	require.ErrorIs(t, err, ErrNoScannableResources)
}

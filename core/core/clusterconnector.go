package core

import (
	"context"
	"errors"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"k8s.io/client-go/dynamic"
)

// OperatorAdapter triggers scans in the Kubescape Operator by creating OperatorCommand objects
// in the cluster and waiting for the operator to execute them.
type OperatorAdapter struct {
	cautils.OperatorScanInfo
	dyn       dynamic.Interface
	namespace string
	timeout   time.Duration
}

func NewOperatorAdapter(scanInfo cautils.OperatorScanInfo, ns string, ctx ...context.Context) (*OperatorAdapter, error) {
	k8sClient := getKubernetesApi()
	if k8sClient == nil || k8sClient.KubernetesClient == nil {
		return nil, errors.New("could not connect to cluster: set --kubeconfig, $KUBECONFIG, or $KUBERNETES_MASTER")
	}
	dyn := k8sClient.GetDynamicClient()
	if dyn == nil {
		return nil, errors.New("could not create a dynamic Kubernetes client")
	}
	return NewOperatorAdapterWithClient(scanInfo, ns, dyn), nil
}

// NewOperatorAdapterWithClient builds an adapter on top of the given dynamic client.
func NewOperatorAdapterWithClient(scanInfo cautils.OperatorScanInfo, ns string, dyn dynamic.Interface) *OperatorAdapter {
	return &OperatorAdapter{
		OperatorScanInfo: scanInfo,
		dyn:              dyn,
		namespace:        ns,
		timeout:          defaultOperatorCommandTimeout,
	}
}

// OperatorScan creates commands and waits for their completion, with a separate timeout for each phase.
func (a *OperatorAdapter) OperatorScan(ctx ...context.Context) (string, error) {
	c := context.Background()
	if len(ctx) > 0 && ctx[0] != nil {
		c = ctx[0]
	}
	payload := a.GetRequestPayload()
	if err := a.ValidatePayload(payload); err != nil {
		return "", err
	}
	if err := c.Err(); err != nil {
		return "", err
	}
	timeout := a.timeout
	if timeout <= 0 {
		timeout = defaultOperatorCommandTimeout
	}
	createCtx, cancel := context.WithTimeout(c, timeout)
	names, err := CreateOperatorCommands(createCtx, a.dyn, a.namespace, *payload)
	cancel()
	if err != nil {
		return "", err
	}
	payloads, err := WaitForOperatorCommandsWithPayloads(c, a.dyn, a.namespace, names, timeout)
	if err != nil {
		return "", err
	}
	logger.L().Info("All operator commands completed")
	if len(names) == 1 && payloads[names[0]] != "" {
		return payloads[names[0]], nil
	}
	return "success", nil
}

func (a *OperatorAdapter) OperatorScanContext(ctx context.Context) (string, error) {
	return a.OperatorScan(ctx)
}

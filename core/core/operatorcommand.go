package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

const (
	operatorCommandGenerateName = "kubescape-cli-"
	operatorCommandPollInterval = 2 * time.Second
	// defaultOperatorCommandTimeout bounds how long the CLI waits for the operator to finish its commands.
	defaultOperatorCommandTimeout = 10 * time.Minute
)

// operatorCommandGVR is the OperatorCommand custom resource the operator watches and executes.
var operatorCommandGVR = schema.GroupVersionResource{Group: "kubescape.io", Version: "v1alpha1", Resource: "operatorcommands"}

// CreateOperatorCommands creates one OperatorCommand object per command, shaped like the ones the
// Helm chart's scheduler creates (helm-charts/charts/kubescape-operator/scripts/create-operator-command.sh),
// and returns the names of the created objects.
func CreateOperatorCommands(ctx context.Context, dyn dynamic.Interface, ns string, cmds apis.Commands) ([]string, error) {
	names := make([]string, 0, len(cmds.Commands))
	for _, cmd := range cmds.Commands {
		body, err := json.Marshal(cmd)
		if err != nil {
			return names, fmt.Errorf("failed to marshal command %q: %w", cmd.CommandName, err)
		}
		guid := cmd.JobTracking.JobID
		if guid == "" {
			guid = uuid.NewString()
		}
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": operatorCommandGVR.GroupVersion().String(),
			"kind":       "OperatorCommand",
			"metadata": map[string]interface{}{
				"generateName": operatorCommandGenerateName,
				"namespace":    ns,
				"labels":       map[string]interface{}{"kubescape.io/app-name": "operator"},
			},
			"spec": map[string]interface{}{
				"guid":        guid,
				"commandType": "OperatorAPI",
				"body":        base64.StdEncoding.EncodeToString(body),
			},
		}}
		created, err := dyn.Resource(operatorCommandGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
		if apierrors.IsNotFound(err) {
			return names, fmt.Errorf("the OperatorCommand resource was not found, please validate that the Kubescape Operator helm chart is installed -> https://github.com/kubescape/helm-charts: %w", err)
		}
		if err != nil {
			return names, fmt.Errorf("failed to create operator command for %q: %w", cmd.CommandName, err)
		}
		logger.L().Info("Created OperatorCommand", helpers.String("name", created.GetName()), helpers.String("command", string(cmd.CommandName)))
		names = append(names, created.GetName())
	}
	return names, nil
}

// WaitForOperatorCommands polls the named OperatorCommands until all report status.completed. A command
// reporting status.error fails the wait immediately.
func WaitForOperatorCommands(ctx context.Context, dyn dynamic.Interface, ns string, names []string, timeout time.Duration) error {
	pending := make(map[string]struct{}, len(names))
	for _, n := range names {
		pending[n] = struct{}{}
	}
	err := wait.PollUntilContextTimeout(ctx, operatorCommandPollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		for _, name := range names {
			if _, ok := pending[name]; !ok {
				continue
			}
			obj, err := dyn.Resource(operatorCommandGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get operator command %s: %w", name, err)
			}
			if msg, found, _ := unstructured.NestedString(obj.Object, "status", "error", "message"); found && msg != "" {
				return false, fmt.Errorf("operator command %s failed: %s", name, msg)
			}
			if _, hasErr, _ := unstructured.NestedMap(obj.Object, "status", "error"); hasErr {
				return false, fmt.Errorf("operator command %s failed", name)
			}
			if done, _, _ := unstructured.NestedBool(obj.Object, "status", "completed"); done {
				delete(pending, name)
			}
		}
		return len(pending) == 0, nil
	})
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if wait.Interrupted(err) {
		return fmt.Errorf("timed out after %s waiting for operator commands", timeout)
	}
	return err
}

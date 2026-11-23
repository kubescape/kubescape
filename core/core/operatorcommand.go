package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// operatorCommandPollInterval is how often WaitForOperatorCommands checks the objects; a variable so tests can shorten it.
var operatorCommandPollInterval = 2 * time.Second

const (
	operatorCommandGenerateName = "kubescape-cli-"
	// defaultOperatorCommandTimeout bounds each phase of creating commands and waiting for completion.
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
	_, err := WaitForOperatorCommandsWithPayloads(ctx, dyn, ns, names, timeout)
	return err
}

// WaitForOperatorCommandsWithPayloads polls the named OperatorCommands until all report status.completed,
// returning a map of command name to completed status payload (decoded string).
func WaitForOperatorCommandsWithPayloads(ctx context.Context, dyn dynamic.Interface, ns string, names []string, timeout time.Duration) (map[string]string, error) {
	started := map[string]bool{}
	// unread holds, for a command whose last read failed with a transient error,
	// that error: the wait cannot say what happened to it.
	unread := map[string]error{}
	payloads := make(map[string]string, len(names))
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
				if isTransientAPIError(err) {
					// Keep polling: a brief API-server hiccup should not fail a command the operator is still running.
					// The other commands are still read, so a failure one of them reports is not held up.
					logger.L().Debug("transient error reading operator command, retrying", helpers.String("name", name), helpers.Error(err))
					unread[name] = err
					continue
				}
				return false, fmt.Errorf("failed to get operator command %s: %w", name, err)
			}
			delete(unread, name)
			if st, _, _ := unstructured.NestedBool(obj.Object, "status", "started"); st {
				started[name] = true
			}
			label := operatorCommandLabel(obj)
			if msg, found, _ := unstructured.NestedString(obj.Object, "status", "error", "message"); found && msg != "" {
				return false, fmt.Errorf("operator command %s failed: %s", label, msg)
			}
			if _, hasErr, _ := unstructured.NestedMap(obj.Object, "status", "error"); hasErr {
				return false, fmt.Errorf("operator command %s failed", label)
			}
			if done, _, _ := unstructured.NestedBool(obj.Object, "status", "completed"); done {
				delete(pending, name)
				if payloadStr, found, _ := unstructured.NestedString(obj.Object, "status", "payload"); found && payloadStr != "" {
					decoded, err := base64.StdEncoding.DecodeString(payloadStr)
					if err == nil {
						payloads[name] = string(decoded)
					} else {
						payloads[name] = payloadStr
					}
				}
			}
		}
		return len(pending) == 0, nil
	})
	if err == nil {
		return payloads, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if wait.Interrupted(err) {
		var stillPending, startedNames []string
		for _, n := range names {
			if _, ok := pending[n]; ok {
				stillPending = append(stillPending, n)
				if started[n] {
					startedNames = append(startedNames, n)
				}
			}
		}
		msg := fmt.Sprintf("timed out after %s waiting for operator commands: still pending: %s", timeout, strings.Join(stillPending, ", "))
		var unreadErrs []string
		for _, n := range stillPending {
			if readErr, ok := unread[n]; ok {
				unreadErrs = append(unreadErrs, fmt.Sprintf("%s: %v", n, readErr))
			}
		}
		if len(unreadErrs) > 0 {
			msg = fmt.Sprintf("%s; last error reading %s", msg, strings.Join(unreadErrs, "; "))
		}
		if len(startedNames) > 0 {
			return nil, fmt.Errorf("%s; started: %s", msg, strings.Join(startedNames, ", "))
		}
		if len(unreadErrs) > 0 {
			// Their status could not be read, so whether they started is not known.
			return nil, errors.New(msg)
		}
		return nil, fmt.Errorf("%s; none of them started: the operator may be down or too old to execute OperatorAPI commands; check the operator pod in namespace %s", msg, ns)
	}
	return nil, err
}

// operatorCommandLabel renders "<CommandName> (<object name>)", reading the command name from spec.body.
func operatorCommandLabel(obj *unstructured.Unstructured) string {
	name := obj.GetName()
	body, _, _ := unstructured.NestedString(obj.Object, "spec", "body")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return name
	}
	var cmd apis.Command
	if json.Unmarshal(raw, &cmd) != nil || cmd.CommandName == "" {
		return name
	}
	return fmt.Sprintf("%s (%s)", cmd.CommandName, name)
}

// isTransientAPIError reports whether err is a temporary API-server condition
// that is worth retrying rather than failing the wait.
func isTransientAPIError(err error) bool {
	return apierrors.IsServerTimeout(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err)
}

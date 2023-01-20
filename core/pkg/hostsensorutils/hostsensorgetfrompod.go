package hostsensorutils

import (
	"context"
	"errors"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"golang.org/x/sync/errgroup"
)

// getPodList clones the internal list of pods being watched as a map of pod names.
func (hsh *HostSensorHandler) getPodList() map[string]string {
	hsh.podListLock.RLock()
	res := make(map[string]string, len(hsh.hostSensorPodNames))
	for k, v := range hsh.hostSensorPodNames {
		res[k] = v
	}
	hsh.podListLock.RUnlock()

	return res
}

// httpGetToPod sends a request to the host-scanner for a pod using the HostSensorPort.
func (hsh *HostSensorHandler) httpGetToPod(ctx context.Context, podName, path string) ([]byte, error) {
	restProxy := hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.daemonSet.Namespace).ProxyGet("http", podName, fmt.Sprintf("%d", hsh.hostSensorPort), path, map[string]string{})
	return restProxy.DoRaw(ctx)
}

// getResourcesFromPod sends a request to a target pod and packs the response as a hostSensorDataEnvelope.
//
// It fills the raw bytes response in the envelope and the node name, but not the GroupVersionKind
// so the caller is responsible to convert the raw data to some structured data and add the GroupVersionKind details.
//
// Special cases for responses:
// * KubeletCommandLine is rearranged and keyed with "fullCommand"
// * KubeletConfiguration is rearranged from raw YAML to JSON
// * Version is reformatted to remove quotes and new lines
func (hsh *HostSensorHandler) getResourcesFromPod(ctx context.Context, podName, nodeName string, resourceKind scannerResource, path string) (hostsensor.HostSensorDataEnvelope, error) {
	buf, err := hsh.httpGetToPod(ctx, podName, path)
	if err != nil {
		return hostsensor.HostSensorDataEnvelope{}, err
	}

	var envelope hostsensor.HostSensorDataEnvelope
	envelope.SetApiVersion(k8sinterface.JoinGroupVersion(hostsensor.GroupHostSensor, hostsensor.Version))
	envelope.SetKind(resourceKind.String())
	envelope.SetName(nodeName)
	envelope.SetData(buf)

	switch resourceKind {
	case KubeletCommandLine:
		reformatKubeletCommandLine(&envelope)
	case KubeletConfiguration:
		if e := reformatKubeletConfiguration(&envelope); e != nil {
			return envelope, err
		}
	case Version:
		reformatVersion(&envelope)
	}

	return envelope, nil
}

// forwardToPod is currently not implemented.
func (hsh *HostSensorHandler) forwardToPod(podName, path string) ([]byte, error) {
	// NOT IN USE:
	// ---
	// spawn port forwarding
	// req := hsh.k8sObj.KubernetesClient.CoreV1().RESTClient().Post()
	// req = req.Name(podName)
	// req = req.Namespace(hsh.DaemonSet.Namespace)
	// req = req.Resource("pods")
	// req = req.SubResource("portforward")
	// ----
	// https://github.com/gianarb/kube-port-forward
	// fullPath := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward",
	// 	hsh.DaemonSet.Namespace, podName)
	// transport, upgrader, err := spdy.RoundTripperFor(hsh.k8sObj.KubernetesClient.config)
	// if err != nil {
	// 	return nil, err
	// }
	// hostIP := strings.TrimLeft(req.RestConfig.Host, "htps:/")
	// dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, &url.URL{Scheme: "http", Path: path, Host: hostIP})
	return nil, errors.New("not implemented")
}

// getVersion returns the version of the deployed host scanner.
//
// At this moment, this method is not in use. It is added as an internal helper to testability.
//
// NOTE: this is hydrated by CollectResources(): we pick the version from the first responding pod.
func (hsh *HostSensorHandler) getVersion() string {
	return string(hsh.version)
}

// CollectResources collects all required information about all the pods for this host.
func (hsh *HostSensorHandler) CollectResources(parentCtx context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	if hsh.daemonSet == nil {
		logger.L().Warning("The host-scanner is not deployed as a daemon set: scanning skipped")

		return []hostsensor.HostSensorDataEnvelope{}, nil, nil
	}
	logger.L().Debug("Accessing host scanner")

	statusMap := make(map[string]apis.StatusInfo) // status of collected responses
	podList := hsh.getPodList()                   // take a snapshot of the pods currently deployed
	size := len(podList)
	results := make([]hostsensor.HostSensorDataEnvelope, 0, 12*size)
	collectGroup, ctx := errgroup.WithContext(parentCtx)
	pool := newWorkerPool(
		ctx,
		hsh.getResourcesFromPod,
		poolWithPods(podList),
		poolWithMaxWorkers(10),
	)
	var version []byte
	condIfNotCloudProvider := make(chan bool)

	collectGroup.Go(func() error {
		// collect responses from the host-scanner API.
		// If an error is encountered, update the StatusInfo map.
		defer func() {
			close(condIfNotCloudProvider)
		}()
		var isCondResolved bool

		for kcData := range pool.Results() {
			if kcData.Err != nil {
				if kcData.Kind != Version {
					addInfoToMap(kcData.Kind, statusMap, kcData.Err)
				}
				logger.L().Ctx(ctx).Warning(kcData.Err.Error())

				continue
			}

			if kcData.IsEmpty() {
				continue
			}

			switch kcData.Kind {
			case Version:
				// interpret the version check response (version is for logging only).
				// Only the first response will get processed.
				if len(version) == 0 {
					version = kcData.Payload.GetData()
				}

				// do not append version to the returned results
				continue

			case CloudProviderInfo:
				// interpret the cloud provider response to allow dependent requests to proceed.
				// only the first response determines whether we have a cloud provider or not
				if isCondResolved {
					break
				}

				// resolves the condition
				select {
				case <-ctx.Done():
					return ctx.Err()
				case condIfNotCloudProvider <- !hasCloudProviderInfo(kcData.Payload):
					isCondResolved = true
				}

			}

			results = append(results, kcData.Payload)
		}

		return nil
	})

	collectGroup.Go(func() error {
		// query ControlPlaneInfo whenever there is no cloud provider.
		// This resolves as soon as the cloud provider status is known.
		// NOTE: ControlPlaneInfo is not queried in parallel: we need to wait and determine if the cloud provider info is present.
		//
		// Forthcoming similar dependencies may be handled likewise by adding cases triggered by a designated signalling channel.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cond, isOpen := <-condIfNotCloudProvider:
			if !isOpen || !cond {
				return nil
			}

			if err := pool.QueryPods(ControlPlaneInfo); err != nil {
				return err
			}
		}

		return nil
	})

	var err error

	// Inquire for resources from the deployed host-scanner: all requests are non-blocking
	for _, scannerResource := range []scannerResource{
		CloudProviderInfo,
		Version,
		KubeletConfiguration,
		KubeletCommandLine,
		OsReleaseFile,
		KernelVersion,
		LinuxSecurityHardeningStatus,
		OpenPortsList,
		LinuxKernelVariables,
		KubeletInfo,
		KubeProxyInfo,
		CNIInfo,
		// ControlPlaneInfo is queried separately if and only if CloudProviderInfo returned an empty provider
	} {
		if err = pool.QueryPods(scannerResource); err != nil {
			break
		}
	}

	errPool := pool.Close()
	errCollect := collectGroup.Wait()

	if err != nil || errPool != nil || errCollect != nil {
		// query posting or data collection returned a blocking error, e.g. the parent context has been cancelled
		switch {
		case err != nil:
		case errPool != nil:
			err = errPool
		case errCollect != nil:
			err = errCollect
		}

		logger.L().Ctx(ctx).Warning("failed to get data", helpers.Error(err))

		return results, statusMap, err
	}

	if len(version) > 0 {
		logger.L().Info(fmt.Sprintf("Host scanner version : %s", version))
		hsh.version = version
	} else {
		logger.L().Info("Unknown host scanner version")
	}

	logger.L().Debug("Done reading information from the host scanner")

	return results, statusMap, nil
}

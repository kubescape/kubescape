package hostsensorutils

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"sync"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	//go:embed hostsensor.yaml
	hostSensorYAML      string
	namespaceWasPresent bool
)

const portName string = "scanner"

// HostSensorHandler is a client that interacts with a host-scanner component deployed on nodes.
//
// The API exposed by the host sensor is defined here: https://github.com/kubescape/host-scanner
type HostSensorHandler struct {
	hostSensorPort                int32
	hostSensorPodNames            map[string]string //map from pod names to node names
	hostSensorUnscheduledPodNames map[string]string //map from pod names to node names
	k8sObj                        *k8sinterface.KubernetesApi
	daemonSet                     *appsv1.DaemonSet
	podListLock                   sync.RWMutex
	gracePeriod                   int64
	workerPool                    workerPool
}

// NewHostSensorHandler builds a new http client to the host-scanner API.
func NewHostSensorHandler(k8sObj *k8sinterface.KubernetesApi, hostSensorYAMLFile string) (*HostSensorHandler, error) {
	if k8sObj == nil {
		return nil, fmt.Errorf("nil k8s interface received")
	}

	if hostSensorYAMLFile != "" {
		d, err := loadHostSensorFromFile(hostSensorYAMLFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load host-scanner yaml file, reason: %w", err)
		}
		hostSensorYAML = d
	}

	hsh := &HostSensorHandler{
		k8sObj:                        k8sObj,
		hostSensorPodNames:            map[string]string{},
		hostSensorUnscheduledPodNames: map[string]string{},
		gracePeriod:                   int64(15),
		workerPool:                    newWorkerPool(),
	}

	// Don't deploy on a cluster with no nodes. Some cloud providers prevent the termination of K8s objects for cluster with no nodes!!!
	if nodeList, err := k8sObj.KubernetesClient.CoreV1().Nodes().List(k8sObj.Context, metav1.ListOptions{}); err != nil || len(nodeList.Items) == 0 {
		if err == nil {
			err = fmt.Errorf("no nodes to scan")
		}
		return hsh, fmt.Errorf("in NewHostSensorHandler, failed to get nodes list: %v", err)
	}

	return hsh, nil
}

// Init deploys the host-scanner and start watching the pods on the host.
func (hsh *HostSensorHandler) Init(ctx context.Context) error {
	// deploy the YAML
	// store namespace + port
	// store pod names
	// make sure all pods are running, after X seconds treat has running anyway, and log an error on the pods not running yet
	logger.L().Info("Installing host scanner")

	// log is used to avoid log duplication
	// coming from the different host-scanner instances
	log := NewLogCoupling()

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	if err := hsh.applyYAML(ctx); err != nil {
		return fmt.Errorf("failed to apply host scanner YAML, reason: %v", err)
	}

	hsh.populatePodNamesToNodeNames(ctx, log)
	if err := hsh.checkPodForEachNode(); err != nil {
		logger.L().Ctx(ctx).Warning(failedToValidateHostSensorPodStatus, helpers.Error(err))
	}

	return nil
}

// checkNamespaceWasPresent check if the given namespace was already present on kubernetes and in "Active" state.
// Return true in case it find the namespace on the list, false otherwise.
// In case we have some error with the kubernetes APIs, it returns an error.
func (hsh *HostSensorHandler) checkNamespaceWasPresent(namespace string) bool {
	ns, err := hsh.k8sObj.KubernetesClient.
		CoreV1().
		Namespaces().
		Get(hsh.k8sObj.Context, namespace, metav1.GetOptions{})
	if err != nil {
		return false
	}

	// check also if it is in "Active" state.
	if ns.Status.Phase != corev1.NamespaceActive {
		return false
	}

	return true
}

// namespaceWasPresent return the namespaceWasPresent variable value.
func (hsh *HostSensorHandler) namespaceWasPresent() bool {
	return namespaceWasPresent
}

func (hsh *HostSensorHandler) applyYAML(ctx context.Context) error {
	workloads, err := cautils.ReadFile([]byte(hostSensorYAML), cautils.YAML_FILE_FORMAT)
	if err != nil {
		return fmt.Errorf("failed to read YAML files, reason: %v", err)
	}

	// Get namespace name
	namespaceName := cautils.GetConfigMapNamespace()
	for i := range workloads {
		if workloads[i].GetKind() == "Namespace" {
			namespaceName = workloads[i].GetName()
			break
		}
	}
	// check if namespace was already present on kubernetes
	namespaceWasPresent = hsh.checkNamespaceWasPresent(namespaceName)

	// Update workload data before applying
	for i := range workloads {
		w := workloadinterface.NewWorkloadObj(workloads[i].GetObject())
		if w == nil {
			return fmt.Errorf("invalid workload: %v", workloads[i].GetObject())
		}
		// set namespace in all objects
		if w.GetKind() != "Namespace" {
			logger.L().Debug("Setting namespace", helpers.String("kind", w.GetKind()), helpers.String("name", w.GetName()), helpers.String("namespace", namespaceName))
			w.SetNamespace(namespaceName)
		}
		// Get container port
		if w.GetKind() == "DaemonSet" {
			containers, err := w.GetContainers()
			if err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Ctx(ctx).Warning(failedToTeardownNamespace, helpers.Error(erra))
				}
				return fmt.Errorf("container not found in DaemonSet: %v", err)
			}
			for j := range containers {
				for k := range containers[j].Ports {
					if containers[j].Ports[k].Name == portName {
						hsh.hostSensorPort = containers[j].Ports[k].ContainerPort
					}
				}
			}
		}

		// Apply workload
		var newWorkload k8sinterface.IWorkload
		var e error

		if g, err := hsh.k8sObj.GetWorkload(w.GetNamespace(), w.GetKind(), w.GetName()); err == nil && g != nil {
			newWorkload, e = hsh.k8sObj.UpdateWorkload(w)
		} else {
			newWorkload, e = hsh.k8sObj.CreateWorkload(w)
		}
		if e != nil {
			if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
				logger.L().Ctx(ctx).Warning(failedToTeardownNamespace, helpers.Error(erra))
			}
			return fmt.Errorf("failed to create/update YAML, reason: %v", e)
		}

		// Save DaemonSet
		if newWorkload.GetKind() == "DaemonSet" {
			b, err := json.Marshal(newWorkload.GetObject())
			if err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Ctx(ctx).Warning(failedToTeardownNamespace, helpers.Error(erra))
				}
				return fmt.Errorf("failed to Marshal YAML of DaemonSet, reason: %v", err)
			}
			var ds appsv1.DaemonSet
			if err := json.Unmarshal(b, &ds); err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Ctx(ctx).Warning(failedToTeardownNamespace, helpers.Error(erra))
				}
				return fmt.Errorf("failed to Unmarshal YAML of DaemonSet, reason: %v", err)
			}
			hsh.daemonSet = &ds
		}
	}

	return nil
}

func (hsh *HostSensorHandler) checkPodForEachNode() error {
	deadline := time.Now().Add(time.Second * 100)
	for {
		nodesList, err := hsh.k8sObj.KubernetesClient.CoreV1().Nodes().List(hsh.k8sObj.Context, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("in checkPodsForEveryNode, failed to get nodes list: %v", nodesList)
		}

		hsh.podListLock.RLock()
		podsNum := len(hsh.hostSensorPodNames)
		unschedPodNum := len(hsh.hostSensorUnscheduledPodNames)
		hsh.podListLock.RUnlock()
		if len(nodesList.Items) <= podsNum+unschedPodNum {
			break
		}

		if time.Now().After(deadline) {
			hsh.podListLock.RLock()
			podsMap := hsh.hostSensorPodNames
			hsh.podListLock.RUnlock()
			return fmt.Errorf("host-scanner pods number (%d) differ than nodes number (%d) after deadline exceeded. Kubescape will take data only from the pods below: %v",
				podsNum, len(nodesList.Items), podsMap)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// initiating routine to keep pod list updated
func (hsh *HostSensorHandler) populatePodNamesToNodeNames(ctx context.Context, log *LogsMap) {
	go func() {
		var watchRes watch.Interface
		var err error
		watchRes, err = hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.daemonSet.Namespace).Watch(hsh.k8sObj.Context, metav1.ListOptions{
			Watch:         true,
			LabelSelector: fmt.Sprintf("name=%s", hsh.daemonSet.Spec.Template.Labels["name"]),
		})
		if err != nil {
			logger.L().Ctx(ctx).Warning(failedToWatchOverDaemonSetPods, helpers.Error(err))
		}
		if watchRes == nil {
			logger.L().Ctx(ctx).Error("failed to watch over DaemonSet pods, will not be able to get host-scanner data")
			return
		}

		for eve := range watchRes.ResultChan() {
			pod, ok := eve.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			go hsh.updatePodInListAtomic(ctx, eve.Type, pod, log)
		}
	}()
}

func (hsh *HostSensorHandler) updatePodInListAtomic(ctx context.Context, eventType watch.EventType, podObj *corev1.Pod, log *LogsMap) {
	hsh.podListLock.Lock()
	defer hsh.podListLock.Unlock()

	switch eventType {
	case watch.Added, watch.Modified:
		if podObj.Status.Phase == corev1.PodRunning && len(podObj.Status.ContainerStatuses) > 0 &&
			podObj.Status.ContainerStatuses[0].Ready {
			hsh.hostSensorPodNames[podObj.ObjectMeta.Name] = podObj.Spec.NodeName
			delete(hsh.hostSensorUnscheduledPodNames, podObj.ObjectMeta.Name)
		} else {
			if podObj.Status.Phase == corev1.PodPending && len(podObj.Status.Conditions) > 0 &&
				podObj.Status.Conditions[0].Reason == corev1.PodReasonUnschedulable {
				nodeName := ""
				if podObj.Spec.Affinity != nil && podObj.Spec.Affinity.NodeAffinity != nil &&
					podObj.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil &&
					len(podObj.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms) > 0 &&
					len(podObj.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields) > 0 &&
					len(podObj.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Values) > 0 {
					nodeName = podObj.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Values[0]
				}
				if !log.isDuplicated(oneHostSensorPodIsUnabledToSchedule) {
					logger.L().Ctx(ctx).Warning(oneHostSensorPodIsUnabledToSchedule,
						helpers.String("message", podObj.Status.Conditions[0].Message))
					log.update(oneHostSensorPodIsUnabledToSchedule)
				}
				if nodeName != "" {
					hsh.hostSensorUnscheduledPodNames[podObj.ObjectMeta.Name] = nodeName
				}
			} else {
				delete(hsh.hostSensorPodNames, podObj.ObjectMeta.Name)
			}
		}
	default:
		delete(hsh.hostSensorPodNames, podObj.ObjectMeta.Name)
	}
}

// tearDownNamespace manage the host-scanner deletion.
func (hsh *HostSensorHandler) tearDownHostScanner(namespace string) error {
	client := hsh.k8sObj.KubernetesClient

	// delete host-scanner DaemonSet
	err := client.AppsV1().
		DaemonSets(namespace).
		Delete(
			hsh.k8sObj.Context,
			hsh.daemonSet.Name,
			metav1.DeleteOptions{
				GracePeriodSeconds: &hsh.gracePeriod,
			},
		)
	if err != nil {
		return fmt.Errorf("failed to delete host-scanner DaemonSet: %v", err)
	}

	// wait for DaemonSet to be deleted
	err = hsh.waitHostScannerDeleted(hsh.k8sObj.Context)
	if err != nil {
		return fmt.Errorf("failed to delete host-scanner DaemonSet: %v", err)
	}

	return nil
}

// tearDownNamespace manage the given namespace deletion.
// At first, it checks if the namespace was already present before installing host-scanner.
// In that case skips the deletion.
// If was not, then patches the namespace in order to remove the finalizers,
// and finally delete the it.
func (hsh *HostSensorHandler) tearDownNamespace(namespace string) error {
	// if namespace was already present on kubernetes (before installing host-scanner),
	// then we shouldn't delete it.
	if hsh.namespaceWasPresent() {
		return nil
	}
	// to make it more readable we store the object client in a variable
	client := hsh.k8sObj.KubernetesClient

	// prepare patch json to remove finalizers from namespace
	patchData := `
	[
		{
			"op": "replace",
			"path": "/metadata/finalizers",
			"value": []
		}
	]
	`
	// patch namespace object removing finalizers
	_, err := client.CoreV1().
		Namespaces().
		Patch(
			hsh.k8sObj.Context,
			namespace,
			types.JSONPatchType,
			[]byte(patchData),
			metav1.PatchOptions{},
		)
	if err != nil {
		return fmt.Errorf("failed to remove finalizers from Namespace: %v", err)
	}

	// patch namespace object removing finalizers
	// delete namespace object
	err = client.CoreV1().
		Namespaces().
		Delete(
			hsh.k8sObj.Context,
			namespace,
			metav1.DeleteOptions{
				GracePeriodSeconds: &hsh.gracePeriod,
			},
		)
	if err != nil {
		return fmt.Errorf("failed to delete %s Namespace: %v", namespace, err)
	}

	return nil
}

func (hsh *HostSensorHandler) TearDown() error {
	namespace := hsh.GetNamespace()
	// delete DaemonSet
	if err := hsh.tearDownHostScanner(namespace); err != nil {
		return fmt.Errorf("failed to delete host-scanner DaemonSet: %v", err)
	}
	// delete Namespace
	if err := hsh.tearDownNamespace(namespace); err != nil {
		return fmt.Errorf("failed to delete host-scanner Namespace: %v", err)
	}

	return nil
}

func (hsh *HostSensorHandler) GetNamespace() string {
	if hsh.daemonSet == nil {
		return ""
	}
	return hsh.daemonSet.Namespace
}

func loadHostSensorFromFile(hostSensorYAMLFile string) (string, error) {
	dat, err := os.ReadFile(hostSensorYAMLFile)
	if err != nil {
		return "", err
	}

	if len(dat) == 0 {
		return "", fmt.Errorf("empty file")
	}

	if !cautils.IsYaml(hostSensorYAMLFile) {
		return "", fmt.Errorf("invalid file format")
	}

	return string(dat), err
}

// waitHostScannerDeleted watch for host-scanner deletion.
// In case it fails it returns an error.
func (hsh *HostSensorHandler) waitHostScannerDeleted(ctx context.Context) error {
	labelSelector := fmt.Sprintf("name=%s", hsh.daemonSet.Name)
	opts := metav1.ListOptions{
		TypeMeta:      metav1.TypeMeta{},
		LabelSelector: labelSelector,
		FieldSelector: "",
	}
	watcher, err := hsh.k8sObj.KubernetesClient.CoreV1().
		Pods(hsh.daemonSet.Namespace).
		Watch(ctx, opts)
	if err != nil {
		return err
	}
	defer watcher.Stop()

	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Type == watch.Deleted {
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}

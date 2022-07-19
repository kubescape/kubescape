package hostsensorutils

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	//go:embed hostsensor.yaml
	hostSensorYAML string
)

const PortName string = "scanner"

type HostSensorHandler struct {
	HostSensorPort                int32
	HostSensorPodNames            map[string]string //map from pod names to node names
	HostSensorUnscheduledPodNames map[string]string //map from pod names to node names
	IsReady                       <-chan bool       //readonly chan
	k8sObj                        *k8sinterface.KubernetesApi
	DaemonSet                     *appsv1.DaemonSet
	podListLock                   sync.RWMutex
	gracePeriod                   int64
	workerPool                    workerPool
}

func NewHostSensorHandler(k8sObj *k8sinterface.KubernetesApi, hostSensorYAMLFile string) (*HostSensorHandler, error) {

	if k8sObj == nil {
		return nil, fmt.Errorf("nil k8s interface received")
	}
	if hostSensorYAMLFile != "" {
		d, err := loadHostSensorFromFile(hostSensorYAMLFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load host-scan yaml file, reason: %s", err.Error())
		}
		hostSensorYAML = d
	}
	hsh := &HostSensorHandler{
		k8sObj:                        k8sObj,
		HostSensorPodNames:            map[string]string{},
		HostSensorUnscheduledPodNames: map[string]string{},
		gracePeriod:                   int64(15),
		workerPool:                    NewWorkerPool(),
	}
	// Don't deploy on cluster with no nodes. Some cloud providers prevents termination of K8s objects for cluster with no nodes!!!
	if nodeList, err := k8sObj.KubernetesClient.CoreV1().Nodes().List(k8sObj.Context, metav1.ListOptions{}); err != nil || len(nodeList.Items) == 0 {
		if err == nil {
			err = fmt.Errorf("no nodes to scan")
		}
		return hsh, fmt.Errorf("in NewHostSensorHandler, failed to get nodes list: %v", err)
	}

	return hsh, nil
}

func (hsh *HostSensorHandler) Init() error {
	// deploy the YAML
	// store namespace + port
	// store pod names
	// make sure all pods are running, after X seconds treat has running anyway, and log an error on the pods not running yet
	logger.L().Info("Installing host scanner")

	cautils.StartSpinner()

	if err := hsh.applyYAML(); err != nil {
		cautils.StopSpinner()
		return fmt.Errorf("failed to apply host scanner YAML, reason: %v", err)
	}
	hsh.populatePodNamesToNodeNames()
	if err := hsh.checkPodForEachNode(); err != nil {
		logger.L().Error("failed to validate host-sensor pods status", helpers.Error(err))
	}
	cautils.StopSpinner()
	return nil
}

func (hsh *HostSensorHandler) applyYAML() error {
	workloads, err := cautils.ReadFile([]byte(hostSensorYAML), cautils.YAML_FILE_FORMAT)
	if err != nil {
		return fmt.Errorf("failed to read YAML files, reason: %v", err)
	}

	// Get namespace name
	namespaceName := ""
	for i := range workloads {
		if workloads[i].GetKind() == "Namespace" {
			namespaceName = workloads[i].GetName()
			break
		}
	}

	// Update workload data before applying
	for i := range workloads {
		w := workloadinterface.NewWorkloadObj(workloads[i].GetObject())
		if w == nil {
			return fmt.Errorf("invalid workload: %v", workloads[i].GetObject())
		}
		// set namespace in all objects
		if w.GetKind() != "Namespace" {
			w.SetNamespace(namespaceName)
		}
		// Get container port
		if w.GetKind() == "DaemonSet" {
			containers, err := w.GetContainers()
			if err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Warning("failed to tear down namespace", helpers.Error(erra))
				}
				return fmt.Errorf("container not found in DaemonSet: %v", err)
			}
			for j := range containers {
				for k := range containers[j].Ports {
					if containers[j].Ports[k].Name == PortName {
						hsh.HostSensorPort = containers[j].Ports[k].ContainerPort
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
				logger.L().Warning("failed to tear down namespace", helpers.Error(erra))
			}
			return fmt.Errorf("failed to create/update YAML, reason: %v", e)
		}

		// Save DaemonSet
		if newWorkload.GetKind() == "DaemonSet" {
			b, err := json.Marshal(newWorkload.GetObject())
			if err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Warning("failed to tear down namespace", helpers.Error(erra))
				}
				return fmt.Errorf("failed to Marshal YAML of DaemonSet, reason: %v", err)
			}
			var ds appsv1.DaemonSet
			if err := json.Unmarshal(b, &ds); err != nil {
				if erra := hsh.tearDownNamespace(namespaceName); erra != nil {
					logger.L().Warning("failed to tear down namespace", helpers.Error(erra))
				}
				return fmt.Errorf("failed to Unmarshal YAML of DaemonSet, reason: %v", err)
			}
			hsh.DaemonSet = &ds
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
		podsNum := len(hsh.HostSensorPodNames)
		unschedPodNum := len(hsh.HostSensorUnscheduledPodNames)
		hsh.podListLock.RUnlock()
		if len(nodesList.Items) <= podsNum+unschedPodNum {
			break
		}
		if time.Now().After(deadline) {
			hsh.podListLock.RLock()
			podsMap := hsh.HostSensorPodNames
			hsh.podListLock.RUnlock()
			return fmt.Errorf("host-sensor pods number (%d) differ than nodes number (%d) after deadline exceeded. Kubescape will take data only from the pods below: %v",
				podsNum, len(nodesList.Items), podsMap)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// initiating routine to keep pod list updated
func (hsh *HostSensorHandler) populatePodNamesToNodeNames() {

	go func() {
		var watchRes watch.Interface
		var err error
		watchRes, err = hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.DaemonSet.Namespace).Watch(hsh.k8sObj.Context, metav1.ListOptions{
			Watch:         true,
			LabelSelector: fmt.Sprintf("name=%s", hsh.DaemonSet.Spec.Template.Labels["name"]),
		})
		if err != nil {
			logger.L().Error("failed to watch over daemonset pods - are we missing watch pods permissions?", helpers.Error(err))
		}
		if watchRes == nil {
			return
		}
		for eve := range watchRes.ResultChan() {
			pod, ok := eve.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			go hsh.updatePodInListAtomic(eve.Type, pod)
		}
	}()
}

func (hsh *HostSensorHandler) updatePodInListAtomic(eventType watch.EventType, podObj *corev1.Pod) {
	hsh.podListLock.Lock()
	defer hsh.podListLock.Unlock()

	switch eventType {
	case watch.Added, watch.Modified:
		if podObj.Status.Phase == corev1.PodRunning && len(podObj.Status.ContainerStatuses) > 0 &&
			podObj.Status.ContainerStatuses[0].Ready {
			hsh.HostSensorPodNames[podObj.ObjectMeta.Name] = podObj.Spec.NodeName
			delete(hsh.HostSensorUnscheduledPodNames, podObj.ObjectMeta.Name)
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
				logger.L().Warning("One host-sensor pod is unable to schedule on node. We will fail to collect the data from this node",
					helpers.String("message", podObj.Status.Conditions[0].Message),
					helpers.String("nodeName", nodeName),
					helpers.String("podName", podObj.ObjectMeta.Name))
				if nodeName != "" {
					hsh.HostSensorUnscheduledPodNames[podObj.ObjectMeta.Name] = nodeName
				}
			} else {
				delete(hsh.HostSensorPodNames, podObj.ObjectMeta.Name)
			}
		}
	default:
		delete(hsh.HostSensorPodNames, podObj.ObjectMeta.Name)
	}
}

func (hsh *HostSensorHandler) tearDownNamespace(namespace string) error {

	if err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Delete(hsh.k8sObj.Context, namespace, metav1.DeleteOptions{GracePeriodSeconds: &hsh.gracePeriod}); err != nil {
		return fmt.Errorf("failed to delete host-sensor namespace: %v", err)
	}
	return nil
}

func (hsh *HostSensorHandler) TearDown() error {
	namespace := hsh.GetNamespace()
	if err := hsh.k8sObj.KubernetesClient.AppsV1().DaemonSets(hsh.GetNamespace()).Delete(hsh.k8sObj.Context, hsh.DaemonSet.Name, metav1.DeleteOptions{GracePeriodSeconds: &hsh.gracePeriod}); err != nil {
		return fmt.Errorf("failed to delete host-sensor daemonset: %v", err)
	}
	if err := hsh.tearDownNamespace(namespace); err != nil {
		return fmt.Errorf("failed to delete host-sensor daemonset: %v", err)
	}
	// TODO: wait for termination? may take up to 120 seconds!!!

	return nil
}

func (hsh *HostSensorHandler) GetNamespace() string {
	if hsh.DaemonSet == nil {
		return ""
	}
	return hsh.DaemonSet.Namespace
}

func loadHostSensorFromFile(hostSensorYAMLFile string) (string, error) {
	dat, err := os.ReadFile(hostSensorYAMLFile)
	if err != nil {
		return "", err
	}
	// TODO - Add file validation
	return string(dat), err
}

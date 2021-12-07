package hostsensorutils

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
	appsapplyv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	coreapplyv1 "k8s.io/client-go/applyconfigurations/core/v1"
)

type HostSensorHandler struct {
	HostSensorPort     int32
	HostSensorPodNames map[string]string //map from pod names to node names
	IsReady            <-chan bool       //readonly chan
	k8sObj             *k8sinterface.KubernetesApi
	DaemonSet          *appsv1.DaemonSet
	podListLock        sync.RWMutex
	gracePeriod        int64
}

func NewHostSensorHandler(k8sObj *k8sinterface.KubernetesApi) (*HostSensorHandler, error) {

	if k8sObj == nil {
		return nil, fmt.Errorf("nil k8s interface received")
	}
	hsh := &HostSensorHandler{
		k8sObj:             k8sObj,
		HostSensorPodNames: map[string]string{},
		gracePeriod:        int64(15),
	}
	// Don't deploy on cluster with no nodes. Some cloud providers prevents termination of K8s objects for cluster with no nodes!!!
	if nodeList, err := k8sObj.KubernetesClient.NodeV1().RuntimeClasses().List(k8sObj.Context, metav1.ListOptions{}); err != nil || len(nodeList.Items) == 0 {
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
	cautils.ProgressTextDisplay("Installing host sensor")
	cautils.StartSpinner()
	defer cautils.StopSpinner()
	if err := hsh.applyYAML(); err != nil {
		return fmt.Errorf("in HostSensorHandler init failed to apply YAML: %v", err)
	}
	hsh.populatePodNamesToNodeNames()
	if err := hsh.checkPodForEachNode(); err != nil {
		fmt.Printf("failed to validate host-sensor pods status: %v", err)
	}
	return nil
}

func (hsh *HostSensorHandler) applyYAML() error {
	dec := yaml.NewDocumentDecoder(io.NopCloser(strings.NewReader(hostSensorYAML)))
	// apply namespace
	singleYAMLBytes := make([]byte, 4096)
	if readLen, err := dec.Read(singleYAMLBytes); err != nil {
		return fmt.Errorf("failed to read YAML of namespace: %v", err)
	} else {
		singleYAMLBytes = singleYAMLBytes[:readLen]
	}
	namespaceAC := &coreapplyv1.NamespaceApplyConfiguration{}
	if err := yaml.Unmarshal(singleYAMLBytes, namespaceAC); err != nil {
		return fmt.Errorf("failed to Unmarshal YAML of namespace: %v", err)
	}
	namespaceName := ""

	if ns, err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Apply(hsh.k8sObj.Context, namespaceAC, metav1.ApplyOptions{
		FieldManager: "kubescape",
	}); err != nil {
		return fmt.Errorf("failed to apply YAML of namespace: %v", err)
	} else {
		namespaceName = ns.Name
	}
	// apply DaemonSet
	daemonAC := &appsapplyv1.DaemonSetApplyConfiguration{}
	singleYAMLBytes = make([]byte, 4096)
	if readLen, err := dec.Read(singleYAMLBytes); err != nil {
		if erra := hsh.tearDownNamesapce(namespaceName); erra != nil {
			err = fmt.Errorf("%v; In addidtion %v", err, erra)
		}
		return fmt.Errorf("failed to read YAML of DaemonSet: %v", err)
	} else {
		singleYAMLBytes = singleYAMLBytes[:readLen]
	}
	if err := yaml.Unmarshal(singleYAMLBytes, daemonAC); err != nil {
		if erra := hsh.tearDownNamesapce(namespaceName); erra != nil {
			err = fmt.Errorf("%v; In addidtion %v", err, erra)
		}
		return fmt.Errorf("failed to Unmarshal YAML of DaemonSet: %v", err)
	}
	daemonAC.Namespace = &namespaceName
	if ds, err := hsh.k8sObj.KubernetesClient.AppsV1().DaemonSets(namespaceName).Apply(hsh.k8sObj.Context, daemonAC, metav1.ApplyOptions{
		FieldManager: "kubescape",
	}); err != nil {
		if erra := hsh.tearDownNamesapce(namespaceName); erra != nil {
			err = fmt.Errorf("%v; In addidtion %v", err, erra)
		}
		return fmt.Errorf("failed to apply YAML of DaemonSet: %v", err)
	} else {
		hsh.HostSensorPort = ds.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort
		hsh.DaemonSet = ds
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
		hsh.podListLock.RUnlock()
		if len(nodesList.Items) == podsNum {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("host-sensor pods number (%d) differ than nodes number (%d) after deadline exceded", podsNum, len(nodesList.Items))
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// initiating routine to keep pod list updated
func (hsh *HostSensorHandler) populatePodNamesToNodeNames() {

	go func() {
		watchRes, err := hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.DaemonSet.Namespace).Watch(hsh.k8sObj.Context, metav1.ListOptions{
			Watch:         true,
			LabelSelector: fmt.Sprintf("name=%s", hsh.DaemonSet.Spec.Template.Labels["name"]),
		})
		if err != nil {
			fmt.Printf("Failed to watch over daemonset pods")
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
		if podObj.Status.Phase == corev1.PodRunning {
			hsh.HostSensorPodNames[podObj.ObjectMeta.Name] = podObj.Spec.NodeName
		} else {
			delete(hsh.HostSensorPodNames, podObj.ObjectMeta.Name)
		}
	default:
		delete(hsh.HostSensorPodNames, podObj.ObjectMeta.Name)
	}
}

func (hsh *HostSensorHandler) tearDownNamesapce(namespace string) error {

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
	if err := hsh.tearDownNamesapce(namespace); err != nil {
		return fmt.Errorf("failed to delete host-sensor daemonset: %v", err)
	}
	// TODO: wait for termination? may take up to 120 seconds!!!

	return nil
}

func (hsh *HostSensorHandler) GetNamespace() string {
	return hsh.DaemonSet.Namespace
}

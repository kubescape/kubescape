package hostsensorutils

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/armosec/k8s-interface/k8sinterface"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/watch"
	appsapplyv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	coreapplyv1 "k8s.io/client-go/applyconfigurations/core/v1"
)

type HostSensorHandler struct {
	HostSensorNamespace     string
	HostSensorPort          int32
	HostSensorDaemonSetName string
	HostSensorPodNames      map[string]string //map from pod names to node names
	IsReady                 <-chan bool       //readonly chan
	k8sObj                  *k8sinterface.KubernetesApi
	DaemonSet               *appsv1.DaemonSet
	podListLock             sync.RWMutex
}

func NewHostSensorHandler(k8sObj *k8sinterface.KubernetesApi) (*HostSensorHandler, error) {
	// deploy the YAML
	// store namespace + port
	// store pod names
	// make sure all pods are running, after X seconds treat has running anyway, and log an error on the pods not running yet
	// return the object
	if k8sObj == nil {
		return nil, fmt.Errorf("nil k8s interface received")
	}
	// Don't deploy on cluster with no nodes. Some cloud providers prevents termination of K8s objects for cluster with no nodes!!!
	if nodeList, err := k8sObj.KubernetesClient.NodeV1().RuntimeClasses().List(k8sObj.Context, metav1.ListOptions{}); err != nil || len(nodeList.Items) == 0 {
		if err == nil {
			err = fmt.Errorf("no nodes to scan")
		}
		return nil, fmt.Errorf("in NewHostSensorHandler, failed to get nodes list: %v", err)
	}
	hsh := &HostSensorHandler{
		k8sObj:             k8sObj,
		HostSensorPodNames: map[string]string{},
	}
	if err := hsh.applyYAML(); err != nil {
		return nil, fmt.Errorf("in NewHostSensorHandler, failed to apply YAML: %v", err)
	}
	hsh.populatePodNamesToNodeNames()
	if err := hsh.checkPodForEachNode(); err != nil {
		fmt.Printf("failed to validate host-sensor pods status: %v", err)
	}
	return hsh, nil
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

	if ns, err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Apply(hsh.k8sObj.Context, namespaceAC, metav1.ApplyOptions{
		FieldManager: "kubescape",
	}); err != nil {
		return fmt.Errorf("failed to apply YAML of namespace: %v", err)
	} else {
		hsh.HostSensorNamespace = ns.Name
	}
	// apply deamonset
	deamonAC := &appsapplyv1.DaemonSetApplyConfiguration{}
	singleYAMLBytes = make([]byte, 4096)
	if readLen, err := dec.Read(singleYAMLBytes); err != nil {
		return fmt.Errorf("failed to read YAML of deamonset: %v", err)
	} else {
		singleYAMLBytes = singleYAMLBytes[:readLen]
	}
	if err := yaml.Unmarshal(singleYAMLBytes, deamonAC); err != nil {
		return fmt.Errorf("failed to Unmarshal YAML of deamonset: %v", err)
	}
	deamonAC.Namespace = &hsh.HostSensorNamespace
	if ds, err := hsh.k8sObj.KubernetesClient.AppsV1().DaemonSets(hsh.HostSensorNamespace).Apply(hsh.k8sObj.Context, deamonAC, metav1.ApplyOptions{
		FieldManager: "kubescape",
	}); err != nil {
		return fmt.Errorf("failed to apply YAML of deamonset: %v", err)
	} else {
		hsh.HostSensorDaemonSetName = ds.Name
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
		time.Sleep(10 * time.Second)
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
				fmt.Printf("Failed to watch over daemonset pods: not a Pod")
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

func (hsh *HostSensorHandler) TearDown() error {
	// remove the namespace
	gracePeriod := int64(15)
	if err := hsh.k8sObj.KubernetesClient.AppsV1().DaemonSets(hsh.HostSensorNamespace).Delete(hsh.k8sObj.Context, hsh.HostSensorDaemonSetName, metav1.DeleteOptions{GracePeriodSeconds: &gracePeriod}); err != nil {
		return fmt.Errorf("failed to delete host-sensor daemonset: %v", err)
	}
	if err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Delete(hsh.k8sObj.Context, hsh.HostSensorNamespace,
		metav1.DeleteOptions{GracePeriodSeconds: &gracePeriod}); err != nil {
		return fmt.Errorf("failed to delete host-sensor namespace: %v", err)
	}
	// TODO: wait for termination

	return nil
}

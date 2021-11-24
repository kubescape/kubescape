package hostsensorutils

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

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

type HostSensorDataEnvelope struct {
	Kind     string            `json:"kind"`
	NodeName string            `json:"nodeName"`
	Data     []json.RawMessage `json:"data"`
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
	hsh := &HostSensorHandler{k8sObj: k8sObj}
	if err := hsh.applyYAML(); err != nil {
		return nil, fmt.Errorf("in NewHostSensorHandler, failed to apply YAML: %v", err)
	}
	return hsh, nil
}

func (hsh *HostSensorHandler) applyYAML() error {
	dec := yaml.NewDocumentDecoder(io.NopCloser(strings.NewReader(hostSensorYAML)))
	// apply namespace
	singleYAMLBytes := make([]byte, 0, 2048)
	if _, err := dec.Read(singleYAMLBytes); err != nil {
		return fmt.Errorf("failed to read YAML of namespace: %v", err)
	}
	namespaceAC := &coreapplyv1.NamespaceApplyConfiguration{}
	if err := yaml.Unmarshal(singleYAMLBytes, namespaceAC); err != nil {
		return fmt.Errorf("failed to Unmarshal YAML of namespace: %v", err)
	}

	if ns, err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Apply(hsh.k8sObj.Context, namespaceAC, metav1.ApplyOptions{}); err != nil {
		return fmt.Errorf("failed to apply YAML of namespace: %v", err)
	} else {
		hsh.HostSensorNamespace = ns.Name
	}
	// apply deamonset
	deamonAC := &appsapplyv1.DaemonSetApplyConfiguration{}
	singleYAMLBytes = make([]byte, 0, 4096)
	if _, err := dec.Read(singleYAMLBytes); err != nil {
		return fmt.Errorf("failed to read YAML of deamonset: %v", err)
	}
	if err := yaml.Unmarshal(singleYAMLBytes, deamonAC); err != nil {
		return fmt.Errorf("failed to Unmarshal YAML of deamonset: %v", err)
	}
	deamonAC.Namespace = &hsh.HostSensorNamespace
	if ds, err := hsh.k8sObj.KubernetesClient.AppsV1().DaemonSets(hsh.HostSensorNamespace).Apply(hsh.k8sObj.Context, deamonAC, metav1.ApplyOptions{}); err != nil {
		return fmt.Errorf("failed to apply YAML of deamonset: %v", err)
	} else {
		hsh.HostSensorDaemonSetName = ds.Name
		hsh.HostSensorPort = ds.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort
		hsh.DaemonSet = ds
	}
	return nil
}

func (hsh *HostSensorHandler) populatePodNamesToNodeNames() error {

	go func() {
		watchRes, err := hsh.k8sObj.KubernetesClient.CoreV1().Pods(hsh.DaemonSet.Namespace).Watch(hsh.k8sObj.Context, metav1.ListOptions{
			Watch:         true,
			LabelSelector: fmt.Sprintf("app=%s", hsh.DaemonSet.Labels["app"]),
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
			hsh.podListLock.Lock()
			switch eve.Type {
			case watch.Added:
				if pod.Status.Phase == corev1.PodRunning {
					hsh.HostSensorPodNames[pod.ObjectMeta.Name] = pod.Spec.NodeName
				} else {
					delete(hsh.HostSensorPodNames, pod.ObjectMeta.Name)
				}
			default:
				delete(hsh.HostSensorPodNames, pod.ObjectMeta.Name)
			}
			hsh.podListLock.Unlock()
		}
	}()

	return nil
}

func (hsh *HostSensorHandler) TearDown() error {
	// remove the namespace
	if err := hsh.k8sObj.KubernetesClient.CoreV1().Namespaces().Delete(hsh.k8sObj.Context, hsh.HostSensorNamespace, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("failed to delete host-sensor namespace: %v", err)
	}
	// TODO: wait for termination

	return nil
}

// return list of
func (hsh *HostSensorHandler) GetKubeletConfigurations() ([][]byte, error) {
	// loop over pods and port-forward it to each of them
	return make([][]byte, 0), nil
}

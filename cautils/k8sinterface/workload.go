package k8sinterface

import (
	"encoding/json"

	"kubescape/cautils/apis"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type IWorkload interface {
	IBasicWorkload

	// Convert
	ToUnstructured() (*unstructured.Unstructured, error)
	ToString() string
	Json() string // DEPRECATED

	// GET
	GetWlid() string
	GetJobID() *apis.JobTracking
	GetVersion() string
	GetGroup() string

	// SET
	SetWlid(string)
	SetInject()
	SetIgnore()
	SetUpdateTime()
	SetJobID(apis.JobTracking)
	SetCompatible()
	SetIncompatible()
	SetReplaceheaders()

	// EXIST
	IsIgnore() bool
	IsInject() bool
	IsAttached() bool
	IsCompatible() bool
	IsIncompatible() bool

	// REMOVE
	RemoveWlid()
	RemoveSecretData()
	RemoveInject()
	RemoveIgnore()
	RemoveUpdateTime()
	RemoveJobID()
	RemoveCompatible()
	RemoveArmoMetadata()
	RemoveArmoLabels()
	RemoveArmoAnnotations()
}
type IBasicWorkload interface {

	// Set
	SetKind(string)
	SetWorkload(map[string]interface{})
	SetLabel(key, value string)
	SetAnnotation(key, value string)
	SetNamespace(string)
	SetName(string)

	// Get
	GetNamespace() string
	GetName() string
	GetGenerateName() string
	GetApiVersion() string
	GetKind() string
	GetInnerAnnotation(string) (string, bool)
	GetPodAnnotation(string) (string, bool)
	GetAnnotation(string) (string, bool)
	GetLabel(string) (string, bool)
	GetAnnotations() map[string]string
	GetInnerAnnotations() map[string]string
	GetPodAnnotations() map[string]string
	GetLabels() map[string]string
	GetInnerLabels() map[string]string
	GetPodLabels() map[string]string
	GetVolumes() ([]corev1.Volume, error)
	GetReplicas() int
	GetContainers() ([]corev1.Container, error)
	GetInitContainers() ([]corev1.Container, error)
	GetOwnerReferences() ([]metav1.OwnerReference, error)
	GetImagePullSecret() ([]corev1.LocalObjectReference, error)
	GetServiceAccountName() string
	GetSelector() (*metav1.LabelSelector, error)
	GetResourceVersion() string
	GetUID() string
	GetPodSpec() (*corev1.PodSpec, error)

	GetWorkload() map[string]interface{}

	// REMOVE
	RemoveLabel(string)
	RemoveAnnotation(string)
	RemovePodStatus()
	RemoveResourceVersion()
}

type Workload struct {
	workload map[string]interface{}
}

func NewWorkload(bWorkload []byte) (*Workload, error) {
	workload := make(map[string]interface{})
	if bWorkload != nil {
		if err := json.Unmarshal(bWorkload, &workload); err != nil {
			return nil, err
		}
	}
	return &Workload{
		workload: workload,
	}, nil
}

func NewWorkloadObj(workload map[string]interface{}) *Workload {
	return &Workload{
		workload: workload,
	}
}

func (w *Workload) Json() string {
	return w.ToString()
}
func (w *Workload) ToString() string {
	if w.GetWorkload() == nil {
		return ""
	}
	bWorkload, err := json.Marshal(w.GetWorkload())
	if err != nil {
		return err.Error()
	}
	return string(bWorkload)
}

func (workload *Workload) DeepCopy(w map[string]interface{}) {
	workload.workload = make(map[string]interface{})
	byt, _ := json.Marshal(w)
	json.Unmarshal(byt, &workload.workload)
}

func (w *Workload) ToUnstructured() (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	if w.workload == nil {
		return obj, nil
	}
	bWorkload, err := json.Marshal(w.workload)
	if err != nil {
		return obj, err
	}
	if err := json.Unmarshal(bWorkload, obj); err != nil {
		return obj, err

	}

	return obj, nil
}

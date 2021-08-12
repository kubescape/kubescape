package k8sinterface

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"kube-escape/cautils/apis"
	"kube-escape/cautils/cautils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ======================================= DELETE ========================================

func (w *Workload) RemoveInject() {
	w.RemovePodLabel(cautils.CAInject)      // DEPRECATED
	w.RemovePodLabel(cautils.CAAttachLabel) // DEPRECATED
	w.RemovePodLabel(cautils.ArmoAttach)

	w.RemoveLabel(cautils.CAInject)      // DEPRECATED
	w.RemoveLabel(cautils.CAAttachLabel) // DEPRECATED
	w.RemoveLabel(cautils.ArmoAttach)
}

func (w *Workload) RemoveIgnore() {
	w.RemovePodLabel(cautils.CAIgnore) // DEPRECATED
	w.RemovePodLabel(cautils.ArmoAttach)

	w.RemoveLabel(cautils.CAIgnore) // DEPRECATED
	w.RemoveLabel(cautils.ArmoAttach)
}

func (w *Workload) RemoveWlid() {
	w.RemovePodAnnotation(cautils.CAWlid) // DEPRECATED
	w.RemovePodAnnotation(cautils.ArmoWlid)

	w.RemoveAnnotation(cautils.CAWlid) // DEPRECATED
	w.RemoveAnnotation(cautils.ArmoWlid)
}

func (w *Workload) RemoveCompatible() {
	w.RemovePodAnnotation(cautils.ArmoCompatibleAnnotation)
}
func (w *Workload) RemoveJobID() {
	w.RemovePodAnnotation(cautils.ArmoJobIDPath)
	w.RemovePodAnnotation(cautils.ArmoJobParentPath)
	w.RemovePodAnnotation(cautils.ArmoJobActionPath)

	w.RemoveAnnotation(cautils.ArmoJobIDPath)
	w.RemoveAnnotation(cautils.ArmoJobParentPath)
	w.RemoveAnnotation(cautils.ArmoJobActionPath)
}
func (w *Workload) RemoveArmoMetadata() {
	w.RemoveArmoLabels()
	w.RemoveArmoAnnotations()
}

func (w *Workload) RemoveArmoAnnotations() {
	l := w.GetAnnotations()
	if l != nil {
		for k := range l {
			if strings.HasPrefix(k, cautils.ArmoPrefix) {
				w.RemoveAnnotation(k)
			}
			if strings.HasPrefix(k, cautils.CAPrefix) { // DEPRECATED
				w.RemoveAnnotation(k)
			}
		}
	}
	lp := w.GetPodAnnotations()
	if lp != nil {
		for k := range lp {
			if strings.HasPrefix(k, cautils.ArmoPrefix) {
				w.RemovePodAnnotation(k)
			}
			if strings.HasPrefix(k, cautils.CAPrefix) { // DEPRECATED
				w.RemovePodAnnotation(k)
			}
		}
	}
}
func (w *Workload) RemoveArmoLabels() {
	l := w.GetLabels()
	if l != nil {
		for k := range l {
			if strings.HasPrefix(k, cautils.ArmoPrefix) {
				w.RemoveLabel(k)
			}
			if strings.HasPrefix(k, cautils.CAPrefix) { // DEPRECATED
				w.RemoveLabel(k)
			}
		}
	}
	lp := w.GetPodLabels()
	if lp != nil {
		for k := range lp {
			if strings.HasPrefix(k, cautils.ArmoPrefix) {
				w.RemovePodLabel(k)
			}
			if strings.HasPrefix(k, cautils.CAPrefix) { // DEPRECATED
				w.RemovePodLabel(k)
			}
		}
	}
}
func (w *Workload) RemoveUpdateTime() {

	// remove from pod
	w.RemovePodAnnotation(cautils.CAUpdate) // DEPRECATED
	w.RemovePodAnnotation(cautils.ArmoUpdate)

	// remove from workload
	w.RemoveAnnotation(cautils.CAUpdate) // DEPRECATED
	w.RemoveAnnotation(cautils.ArmoUpdate)
}

func (w *Workload) RemovePodStatus() {
	delete(w.workload, "status")
}

func (w *Workload) RemoveResourceVersion() {
	if _, ok := w.workload["metadata"]; !ok {
		return
	}
	meta, _ := w.workload["metadata"].(map[string]interface{})
	delete(meta, "resourceVersion")
}

func (w *Workload) RemoveLabel(key string) {
	w.RemoveMetadata([]string{"metadata"}, "labels", key)
}

func (w *Workload) RemoveAnnotation(key string) {
	w.RemoveMetadata([]string{"metadata"}, "annotations", key)
}

func (w *Workload) RemovePodAnnotation(key string) {
	w.RemoveMetadata(PodMetadata(w.GetKind()), "annotations", key)
}

func (w *Workload) RemovePodLabel(key string) {
	w.RemoveMetadata(PodMetadata(w.GetKind()), "labels", key)
}

func (w *Workload) RemoveMetadata(scope []string, metadata, key string) {

	workload := w.workload
	for i := range scope {
		if _, ok := workload[scope[i]]; !ok {
			return
		}
		workload, _ = workload[scope[i]].(map[string]interface{})
	}

	if _, ok := workload[metadata]; !ok {
		return
	}

	labels, _ := workload[metadata].(map[string]interface{})
	delete(labels, key)

}

// ========================================= SET =========================================

func (w *Workload) SetWorkload(workload map[string]interface{}) {
	w.workload = workload
}

func (w *Workload) SetKind(kind string) {
	w.workload["kind"] = kind
}

func (w *Workload) SetInject() {
	w.SetPodLabel(cautils.ArmoAttach, cautils.BoolToString(true))
}

func (w *Workload) SetJobID(jobTracking apis.JobTracking) {
	w.SetPodAnnotation(cautils.ArmoJobIDPath, jobTracking.JobID)
	w.SetPodAnnotation(cautils.ArmoJobParentPath, jobTracking.ParentID)
	w.SetPodAnnotation(cautils.ArmoJobActionPath, fmt.Sprintf("%d", jobTracking.LastActionNumber))
}

func (w *Workload) SetIgnore() {
	w.SetPodLabel(cautils.ArmoAttach, cautils.BoolToString(false))
}

func (w *Workload) SetCompatible() {
	w.SetPodAnnotation(cautils.ArmoCompatibleAnnotation, cautils.BoolToString(true))
}

func (w *Workload) SetIncompatible() {
	w.SetPodAnnotation(cautils.ArmoCompatibleAnnotation, cautils.BoolToString(false))
}

func (w *Workload) SetReplaceheaders() {
	w.SetPodAnnotation(cautils.ArmoReplaceheaders, cautils.BoolToString(true))
}

func (w *Workload) SetWlid(wlid string) {
	w.SetPodAnnotation(cautils.ArmoWlid, wlid)
}

func (w *Workload) SetUpdateTime() {
	w.SetPodAnnotation(cautils.ArmoUpdate, string(time.Now().UTC().Format("02-01-2006 15:04:05")))
}

func (w *Workload) SetNamespace(namespace string) {
	w.SetMetadata([]string{"metadata"}, "namespace", namespace)
}

func (w *Workload) SetName(name string) {
	w.SetMetadata([]string{"metadata"}, "name", name)
}

func (w *Workload) SetLabel(key, value string) {
	w.SetMetadata([]string{"metadata", "labels"}, key, value)
}

func (w *Workload) SetPodLabel(key, value string) {
	w.SetMetadata(append(PodMetadata(w.GetKind()), "labels"), key, value)
}
func (w *Workload) SetAnnotation(key, value string) {
	w.SetMetadata([]string{"metadata", "annotations"}, key, value)
}
func (w *Workload) SetPodAnnotation(key, value string) {
	w.SetMetadata(append(PodMetadata(w.GetKind()), "annotations"), key, value)
}

func (w *Workload) SetMetadata(scope []string, key string, val interface{}) {
	workload := w.workload
	for i := range scope {
		if _, ok := workload[scope[i]]; !ok {
			workload[scope[i]] = make(map[string]interface{})
		}
		workload, _ = workload[scope[i]].(map[string]interface{})
	}

	workload[key] = val
}

// ========================================= GET =========================================
func (w *Workload) GetWorkload() map[string]interface{} {
	return w.workload
}
func (w *Workload) GetNamespace() string {
	if v, ok := InspectWorkload(w.workload, "metadata", "namespace"); ok {
		return v.(string)
	}
	return ""
}

func (w *Workload) GetName() string {
	if v, ok := InspectWorkload(w.workload, "metadata", "name"); ok {
		return v.(string)
	}
	return ""
}

func (w *Workload) GetApiVersion() string {
	if v, ok := InspectWorkload(w.workload, "apiVersion"); ok {
		return v.(string)
	}
	return ""
}

func (w *Workload) GetGenerateName() string {
	if v, ok := InspectWorkload(w.workload, "metadata", "generateName"); ok {
		return v.(string)
	}
	return ""
}

func (w *Workload) GetKind() string {
	if v, ok := InspectWorkload(w.workload, "kind"); ok {
		return v.(string)
	}
	return ""
}
func (w *Workload) GetSelector() (*metav1.LabelSelector, error) {
	selector := &metav1.LabelSelector{}
	if v, ok := InspectWorkload(w.workload, "spec", "selector", "matchLabels"); ok && v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return selector, err
		}
		if err := json.Unmarshal(b, selector); err != nil {
			return selector, err
		}
		return selector, nil
	}
	return selector, nil
}

func (w *Workload) GetAnnotation(annotation string) (string, bool) {
	if v, ok := InspectWorkload(w.workload, "metadata", "annotations", annotation); ok {
		return v.(string), ok
	}
	return "", false
}
func (w *Workload) GetLabel(label string) (string, bool) {
	if v, ok := InspectWorkload(w.workload, "metadata", "labels", label); ok {
		return v.(string), ok
	}
	return "", false
}

func (w *Workload) GetPodLabel(label string) (string, bool) {
	if v, ok := InspectWorkload(w.workload, append(PodMetadata(w.GetKind()), "labels", label)...); ok && v != nil {
		return v.(string), ok
	}
	return "", false
}

func (w *Workload) GetLabels() map[string]string {
	if v, ok := InspectWorkload(w.workload, "metadata", "labels"); ok && v != nil {
		labels := make(map[string]string)
		for k, i := range v.(map[string]interface{}) {
			labels[k] = i.(string)
		}
		return labels
	}
	return nil
}

// GetInnerLabels - DEPRECATED
func (w *Workload) GetInnerLabels() map[string]string {
	return w.GetPodLabels()
}

func (w *Workload) GetPodLabels() map[string]string {
	if v, ok := InspectWorkload(w.workload, append(PodMetadata(w.GetKind()), "labels")...); ok && v != nil {
		labels := make(map[string]string)
		for k, i := range v.(map[string]interface{}) {
			labels[k] = i.(string)
		}
		return labels
	}
	return nil
}

// GetInnerAnnotations - DEPRECATED
func (w *Workload) GetInnerAnnotations() map[string]string {
	return w.GetPodAnnotations()
}

// GetPodAnnotations
func (w *Workload) GetPodAnnotations() map[string]string {
	if v, ok := InspectWorkload(w.workload, append(PodMetadata(w.GetKind()), "annotations")...); ok && v != nil {
		annotations := make(map[string]string)
		for k, i := range v.(map[string]interface{}) {
			annotations[k] = fmt.Sprintf("%v", i)
		}
		return annotations
	}
	return nil
}

// GetInnerAnnotation DEPRECATED
func (w *Workload) GetInnerAnnotation(annotation string) (string, bool) {
	return w.GetPodAnnotation(annotation)
}

func (w *Workload) GetPodAnnotation(annotation string) (string, bool) {
	if v, ok := InspectWorkload(w.workload, append(PodMetadata(w.GetKind()), "annotations", annotation)...); ok && v != nil {
		return v.(string), ok
	}
	return "", false
}

func (w *Workload) GetAnnotations() map[string]string {
	if v, ok := InspectWorkload(w.workload, "metadata", "annotations"); ok && v != nil {
		annotations := make(map[string]string)
		for k, i := range v.(map[string]interface{}) {
			annotations[k] = fmt.Sprintf("%v", i)
		}
		return annotations
	}
	return nil
}

// GetVolumes -
func (w *Workload) GetVolumes() ([]corev1.Volume, error) {
	volumes := []corev1.Volume{}

	interVolumes, _ := InspectWorkload(w.workload, append(PodSpec(w.GetKind()), "volumes")...)
	if interVolumes == nil {
		return volumes, nil
	}
	volumesBytes, err := json.Marshal(interVolumes)
	if err != nil {
		return volumes, err
	}
	err = json.Unmarshal(volumesBytes, &volumes)

	return volumes, err
}

func (w *Workload) GetServiceAccountName() string {

	if v, ok := InspectWorkload(w.workload, append(PodSpec(w.GetKind()), "serviceAccountName")...); ok && v != nil {
		return v.(string)
	}
	return ""
}

func (w *Workload) GetPodSpec() (*corev1.PodSpec, error) {
	podSpec := &corev1.PodSpec{}
	podSepcRaw, _ := InspectWorkload(w.workload, PodSpec(w.GetKind())...)
	if podSepcRaw == nil {
		return podSpec, fmt.Errorf("no PodSpec for workload: %v", w)
	}
	b, err := json.Marshal(podSepcRaw)
	if err != nil {
		return podSpec, err
	}
	err = json.Unmarshal(b, podSpec)

	return podSpec, err
}

func (w *Workload) GetImagePullSecret() ([]corev1.LocalObjectReference, error) {
	imgPullSecrets := []corev1.LocalObjectReference{}

	iImgPullSecrets, _ := InspectWorkload(w.workload, append(PodSpec(w.GetKind()), "imagePullSecrets")...)
	b, err := json.Marshal(iImgPullSecrets)
	if err != nil {
		return imgPullSecrets, err
	}
	err = json.Unmarshal(b, &imgPullSecrets)

	return imgPullSecrets, err
}

// GetContainers -
func (w *Workload) GetContainers() ([]corev1.Container, error) {
	containers := []corev1.Container{}

	interContainers, _ := InspectWorkload(w.workload, append(PodSpec(w.GetKind()), "containers")...)
	if interContainers == nil {
		return containers, nil
	}
	containersBytes, err := json.Marshal(interContainers)
	if err != nil {
		return containers, err
	}
	err = json.Unmarshal(containersBytes, &containers)

	return containers, err
}

// GetContainers -
func (w *Workload) GetInitContainers() ([]corev1.Container, error) {
	containers := []corev1.Container{}

	interContainers, _ := InspectWorkload(w.workload, append(PodSpec(w.GetKind()), "initContainers")...)
	if interContainers == nil {
		return containers, nil
	}
	containersBytes, err := json.Marshal(interContainers)
	if err != nil {
		return containers, err
	}
	err = json.Unmarshal(containersBytes, &containers)

	return containers, err
}

// GetOwnerReferences -
func (w *Workload) GetOwnerReferences() ([]metav1.OwnerReference, error) {
	ownerReferences := []metav1.OwnerReference{}
	interOwnerReferences, ok := InspectWorkload(w.workload, "metadata", "ownerReferences")
	if !ok {
		return ownerReferences, nil
	}

	ownerReferencesBytes, err := json.Marshal(interOwnerReferences)
	if err != nil {
		return ownerReferences, err
	}
	err = json.Unmarshal(ownerReferencesBytes, &ownerReferences)
	if err != nil {
		return ownerReferences, err

	}
	return ownerReferences, nil
}
func (w *Workload) GetResourceVersion() string {
	if v, ok := InspectWorkload(w.workload, "metadata", "resourceVersion"); ok {
		return v.(string)
	}
	return ""
}
func (w *Workload) GetUID() string {
	if v, ok := InspectWorkload(w.workload, "metadata", "uid"); ok {
		return v.(string)
	}
	return ""
}
func (w *Workload) GetWlid() string {
	if wlid, ok := w.GetAnnotation(cautils.ArmoWlid); ok {
		return wlid
	}
	return ""
}

func (w *Workload) GetJobID() *apis.JobTracking {
	jobTracking := apis.JobTracking{}
	if job, ok := w.GetPodAnnotation(cautils.ArmoJobIDPath); ok {
		jobTracking.JobID = job
	}
	if parent, ok := w.GetPodAnnotation(cautils.ArmoJobParentPath); ok {
		jobTracking.ParentID = parent
	}
	if action, ok := w.GetPodAnnotation(cautils.ArmoJobActionPath); ok {
		if i, err := strconv.Atoi(action); err == nil {
			jobTracking.LastActionNumber = i
		}
	}
	if jobTracking.LastActionNumber == 0 { // start the counter at 1
		jobTracking.LastActionNumber = 1
	}
	return &jobTracking
}

// func (w *Workload) GetJobID() string {
// 	if status, ok := w.GetAnnotation(cautils.ArmoJobID); ok {
// 		return status
// 	}
// 	return ""
// }

// ========================================= IS =========================================

func (w *Workload) IsInject() bool {
	return w.IsAttached()
}

func (w *Workload) IsIgnore() bool {
	if attach := cautils.IsAttached(w.GetPodLabels()); attach != nil {
		return !(*attach)
	}
	if attach := cautils.IsAttached(w.GetLabels()); attach != nil {
		return !(*attach)
	}
	return false
}

func (w *Workload) IsCompatible() bool {
	if c, ok := w.GetPodAnnotation(cautils.ArmoCompatibleAnnotation); ok {
		return cautils.StringToBool(c)

	}
	if c, ok := w.GetAnnotation(cautils.ArmoCompatibleAnnotation); ok {
		return cautils.StringToBool(c)

	}
	return false
}

func (w *Workload) IsIncompatible() bool {
	if c, ok := w.GetPodAnnotation(cautils.ArmoCompatibleAnnotation); ok {
		return !cautils.StringToBool(c)
	}
	if c, ok := w.GetAnnotation(cautils.ArmoCompatibleAnnotation); ok {
		return !cautils.StringToBool(c)
	}
	return false
}
func (w *Workload) IsAttached() bool {
	if attach := cautils.IsAttached(w.GetPodLabels()); attach != nil {
		return *attach
	}
	if attach := cautils.IsAttached(w.GetLabels()); attach != nil {
		return *attach
	}
	return false
}

func (w *Workload) IsReplaceheaders() bool {
	if c, ok := w.GetPodAnnotation(cautils.ArmoReplaceheaders); ok {
		return cautils.StringToBool(c)
	}
	return false
}

// ======================================= UTILS =========================================

// InspectWorkload -
func InspectWorkload(workload interface{}, scopes ...string) (val interface{}, k bool) {

	val, k = nil, false
	if len(scopes) == 0 {
		if workload != nil {
			return workload, true
		}
		return nil, false
	}
	if data, ok := workload.(map[string]interface{}); ok {
		val, k = InspectWorkload(data[scopes[0]], scopes[1:]...)
	}
	return val, k

}

// // InspectWorkload -
// func InjectWorkload(workload interface{}, scopes []string, val string) {

// 	if len(scopes) == 0 {

// 	}
// 	if data, ok := workload.(map[string]interface{}); ok {
// 		InjectWorkload(data[scopes[0]], scopes[1:], val)
// 	} else {

// 	}

// }

// InjectWorkload -
// func InjectWorkload(workload interface{}, scopes []string, val string) {

// 	if len(scopes) == 0 {
// 		workload = ""
// 	}
// 	if data, ok := workload.(map[string]interface{}); ok {
// 		d := InjectWorkload(data[scopes[0]], scopes[1:], val)
// 		data[scopes[0]] = d
// 		return data
// 	} else {

// 	}

// }
// func (w *Workload) SetNamespace(ns string) {

// 	if v, k := w.workload["metadata"]; k {
// 		if vv, kk := v.(map[string]interface{}); kk {
// 			vv["namespace"] = ""
// 			// if v3, k3 := w.workload["namespace"]; k3 {
// 			// 	if v4, k4 := v.(map[string]interface{}); kk {

// 			// 	}
// 			// }
// 			v = vv
// 		}
// 		w.workload = v
// 	}
// 	// if data, ok := w.workload.(map[string]interface{}); ok {
// 	// 	val, k = InspectWorkload(data[scopes[0]], scopes[1:]...)
// 	// }

// }

package opaprocessor

import (
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/securityexception"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func (opap *OPAProcessor) emitExceptionMatchEvents(resource workloadinterface.IMetadata, result resourcesresults.Result) {
	if opap.exceptionEventRecorder == nil || resource == nil {
		return
	}

	resourceKind := resource.GetKind()
	resourceName := resource.GetName()
	if resourceKind == "" || resourceName == "" {
		return
	}

	namespace := resource.GetNamespace()
	if namespace == "" {
		namespace = "cluster-scope"
	}

	emitted := map[string]struct{}{}
	resourceID := resource.GetID()

	for _, control := range result.AssociatedControls {
		if control.ControlID == "" {
			continue
		}
		for _, rule := range control.ResourceAssociatedRules {
			for _, exception := range rule.Exception {
				var obj runtime.Object
				var key string
				if ref, ok := securityexception.CRDReferenceFromPolicy(exception); ok {
					key = fmt.Sprintf("crd/%s/%s/%s/%s/%s", ref.Kind, ref.Namespace, ref.Name, control.ControlID, resourceID)
					obj = securityexception.UnstructuredForCRD(ref)
				} else {
					// A file/cloud-sourced exception has no CRD instance of its
					// own to attach the event to, so fall back to the scanned
					// resource the exception was matched against.
					key = fmt.Sprintf("resource/%s/%s", control.ControlID, resourceID)
					obj = &unstructured.Unstructured{Object: resource.GetObject()}
				}
				if _, exists := emitted[key]; exists {
					continue
				}
				emitted[key] = struct{}{}
				opap.exceptionEventRecorder.Eventf(
					obj,
					corev1.EventTypeNormal,
					"ExceptionMatched",
					"Matched control %s on %s/%s in namespace %s",
					control.ControlID,
					resourceKind,
					resourceName,
					namespace,
				)
			}
		}
	}
}

package opaprocessor

import (
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/securityexception"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	corev1 "k8s.io/api/core/v1"
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
				ref, ok := securityexception.CRDReferenceFromPolicy(exception)
				if !ok {
					continue
				}
				key := fmt.Sprintf("%s/%s/%s/%s/%s", ref.Kind, ref.Namespace, ref.Name, control.ControlID, resourceID)
				if _, exists := emitted[key]; exists {
					continue
				}
				emitted[key] = struct{}{}
				obj := securityexception.UnstructuredForCRD(ref)
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

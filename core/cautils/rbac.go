package cautils

import (
	"encoding/json"
	"time"

	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"

	"github.com/google/uuid"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/rbac-utils/rbacscanner"
	"github.com/kubescape/rbac-utils/rbacutils"
)

type RBACObjects struct {
	scanner *rbacscanner.RbacScannerFromK8sAPI
}

func NewRBACObjects(scanner *rbacscanner.RbacScannerFromK8sAPI) *RBACObjects {
	return &RBACObjects{scanner: scanner}
}

func (rbacObjects *RBACObjects) SetResourcesReport() (*reporthandlingv2.PostureReport, error) {
	return &reporthandlingv2.PostureReport{
		ReportID:             uuid.NewString(),
		ReportGenerationTime: time.Now().UTC(),
		CustomerGUID:         rbacObjects.scanner.CustomerGUID,
		ClusterName:          rbacObjects.scanner.ClusterName,
		Metadata: reporthandlingv2.Metadata{
			ContextMetadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{
					ContextName: rbacObjects.scanner.ClusterName,
				},
			},
		},
	}, nil
}

func (rbacObjects *RBACObjects) ListAllResources() (map[string]workloadinterface.IMetadata, error) {
	resources, err := rbacObjects.scanner.ListResources()
	if err != nil {
		return nil, err
	}
	allresources, err := rbacObjects.rbacObjectsToResources(resources)
	if err != nil {
		return nil, err
	}
	return allresources, nil
}

func (rbacObjects *RBACObjects) rbacObjectsToResources(resources *rbacutils.RbacObjects) (map[string]workloadinterface.IMetadata, error) {
	allresources := map[string]workloadinterface.IMetadata{}

	/*
		************************************************************************************************************************
			This code is adding a non valid ID ->
				(github.com/kubescape/opa-utils v0.0.11): "//SA2WLIDmap/SA2WLIDmap"
				(github.com/kubescape/opa-utils v0.0.12): "armo.rbac.com/v0beta1//SAID2WLIDmap/SAID2WLIDmap"

			Should be investigated
		************************************************************************************************************************
	*/

	// wrap rbac aggregated objects in IMetadata and add to AllResources
	// TODO - DEPRECATE SA2WLIDmap
	m, err := rbacutils.SA2WLIDmapIMetadataWrapper(resources.SA2WLIDmap)
	if err != nil {
		return nil, err
	}

	sa2WLIDmapIMeta := workloadinterface.NewBaseObject(m)
	allresources[sa2WLIDmapIMeta.GetID()] = sa2WLIDmapIMeta

	m2, err := rbacutils.SAID2WLIDmapIMetadataWrapper(resources.SAID2WLIDmap)
	if err != nil {
		return nil, err
	}

	saID2WLIDmapIMeta := workloadinterface.NewBaseObject(m2)
	allresources[saID2WLIDmapIMeta.GetID()] = saID2WLIDmapIMeta

	// convert rbac k8s resources to IMetadata and add to allresources
	for _, cr := range resources.ClusterRoles.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crmap["apiVersion"] = "rbac.authorization.k8s.io/v1" // TODO - is the the correct apiVersion?
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("ClusterRole")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.Roles.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crmap["apiVersion"] = "rbac.authorization.k8s.io/v1" // TODO - is the the correct apiVersion?
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("Role")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.ClusterRoleBindings.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crmap["apiVersion"] = "rbac.authorization.k8s.io/v1" // TODO - is the the correct apiVersion?
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("ClusterRoleBinding")
		allresources[crIMeta.GetID()] = crIMeta
	}
	for _, cr := range resources.RoleBindings.Items {
		crmap, err := convertToMap(cr)
		if err != nil {
			return nil, err
		}
		crmap["apiVersion"] = "rbac.authorization.k8s.io/v1" // TODO - is the the correct apiVersion?
		crIMeta := workloadinterface.NewWorkloadObj(crmap)
		crIMeta.SetKind("RoleBinding")
		allresources[crIMeta.GetID()] = crIMeta
	}
	return allresources, nil
}

func convertToMap(obj interface{}) (map[string]interface{}, error) {
	var inInterface map[string]interface{}
	inrec, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(inrec, &inInterface)
	if err != nil {
		return nil, err
	}
	return inInterface, nil
}

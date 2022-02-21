package cautils

import (
	"encoding/json"
	"time"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/rbac-utils/rbacscanner"
	"github.com/armosec/rbac-utils/rbacutils"
	"github.com/google/uuid"
)

type RBACObjects struct {
	scanner *rbacscanner.RbacScannerFromK8sAPI
}

func NewRBACObjects(scanner *rbacscanner.RbacScannerFromK8sAPI) *RBACObjects {
	return &RBACObjects{scanner: scanner}
}

func (rbacObjects *RBACObjects) SetResourcesReport() (*reporthandling.PostureReport, error) {
	return &reporthandling.PostureReport{
		ReportID:             uuid.NewString(),
		ReportGenerationTime: time.Now().UTC(),
		CustomerGUID:         rbacObjects.scanner.CustomerGUID,
		ClusterName:          rbacObjects.scanner.ClusterName,
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
				(github.com/armosec/rbac-utils v0.0.11): "//SA2WLIDmap/SA2WLIDmap"
				(github.com/armosec/rbac-utils v0.0.12): "armo.rbac.com/v0beta1//SAID2WLIDmap/SAID2WLIDmap"

			Should be investigated
		************************************************************************************************************************
	*/

	// wrap rbac aggregated objects in IMetadata and add to allresources
	// TODO - DEPRECATE SA2WLIDmap
	SA2WLIDmapIMeta, err := rbacutils.SA2WLIDmapIMetadataWrapper(resources.SA2WLIDmap)
	if err != nil {
		return nil, err
	}
	allresources[SA2WLIDmapIMeta.GetID()] = SA2WLIDmapIMeta

	SAID2WLIDmapIMeta, err := rbacutils.SAID2WLIDmapIMetadataWrapper(resources.SAID2WLIDmap)
	if err != nil {
		return nil, err
	}
	allresources[SAID2WLIDmapIMeta.GetID()] = SAID2WLIDmapIMeta

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

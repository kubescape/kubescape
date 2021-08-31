package k8sinterface

import (
	"testing"

	"github.com/armosec/kubescape/cautils/cautils"
)

func TestGetGroupVersionResource(t *testing.T) {
	wlid := "wlid://cluster-david-v1/namespace-default/deployment-nginx-deployment"
	r, err := GetGroupVersionResource(cautils.GetKindFromWlid(wlid))
	if err != nil {
		t.Error(err)
		return
	}
	if r.Group != "apps" {
		t.Errorf("wrong group")
	}
	if r.Version != "v1" {
		t.Errorf("wrong Version")
	}
	if r.Resource != "deployments" {
		t.Errorf("wrong Resource")
	}

	r2, err := GetGroupVersionResource("NetworkPolicy")
	if err != nil {
		t.Error(err)
		return
	}
	if r2.Resource != "networkpolicies" {
		t.Errorf("wrong Resource")
	}
}

package cautils

import (
	"testing"
)

// tests wlid parse

func TestSpiffeWLIDToInfoSuccess(t *testing.T) {

	WLID := "wlid://cluster-HipsterShopCluster2/namespace-prod/deployment-cartservice"
	ms, er := SpiffeToSpiffeInfo(WLID)

	if er != nil || ms.Level0 != "HipsterShopCluster2" || ms.Level0Type != "cluster" || ms.Level1 != "prod" || ms.Level1Type != "namespace" ||
		ms.Kind != "deployment" || ms.Name != "cartservice" {
		t.Errorf("TestSpiffeWLIDToInfoSuccess failed to parse %v", WLID)
	}
}

func TestSpiffeSIDInfoSuccess(t *testing.T) {

	SID := "sid://cluster-HipsterShopCluster2/namespace-dev/secret-caregcred"
	ms, er := SpiffeToSpiffeInfo(SID)

	if er != nil || ms.Level0 != "HipsterShopCluster2" || ms.Level0Type != "cluster" || ms.Level1 != "dev" || ms.Level1Type != "namespace" ||
		ms.Kind != "secret" || ms.Name != "caregcred" {
		t.Errorf("TestSpiffeSIDInfoSuccess failed to parse %v", SID)
	}
}

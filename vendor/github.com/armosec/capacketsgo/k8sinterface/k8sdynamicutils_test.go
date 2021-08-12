package k8sinterface

import "testing"

func TestConvertUnstructuredSliceToMap(t *testing.T) {
	converted := ConvertUnstructuredSliceToMap(V1KubeSystemNamespaceMock().Items)
	if len(converted) == 0 { // != 7
		t.Errorf("len(converted) == 0")
	}
}

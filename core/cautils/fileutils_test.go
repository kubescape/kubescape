package cautils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "../examples/online-boutique/*")
}

func TestListFiles(t *testing.T) {

	filesPath := onlineBoutiquePath()

	files, errs := listFiles(filesPath)
	assert.Equal(t, 0, len(errs))
	assert.Equal(t, 12, len(files))
}

func TestLoadResourcesFromFiles(t *testing.T) {
	workloads, err := LoadResourcesFromFiles(onlineBoutiquePath())
	assert.NoError(t, err)
	assert.Equal(t, 12, len(workloads))

	for i, w := range workloads {
		switch filepath.Base(i) {
		case "adservice.yaml":
			assert.Equal(t, 2, len(w))
			assert.Equal(t, "path=L1VzZXJzL2Rhdmlkd2VydGVudGVpbC9hcm1vL3JlcG9zL2t1YmVzY2FwZS9leGFtcGxlcy9vbmxpbmUtYm91dGlxdWUvYWRzZXJ2aWNlLnlhbWw=/apps/v1//Deployment/adservice", w[0].GetID())
			assert.Equal(t, "path=L1VzZXJzL2Rhdmlkd2VydGVudGVpbC9hcm1vL3JlcG9zL2t1YmVzY2FwZS9leGFtcGxlcy9vbmxpbmUtYm91dGlxdWUvYWRzZXJ2aWNlLnlhbWw=//v1//Service/adservice", w[1].GetID())
		}
	}
}
func TestLoadFiles(t *testing.T) {
	files, _ := listFiles(onlineBoutiquePath())
	_, err := loadFiles(files)
	assert.Equal(t, 0, len(err))
}

func TestLoadFile(t *testing.T) {
	files, _ := listFiles(strings.Replace(onlineBoutiquePath(), "*", "adservice.yaml", 1))
	assert.Equal(t, 1, len(files))

	_, err := loadFile(files[0])
	assert.NoError(t, err)
}
func TestMapResources(t *testing.T) {
	// policyHandler := &PolicyHandler{}
	// k8sResources, err := policyHandler.loadResources(opaSessionObj.Frameworks, scanInfo)
	// files, _ := listFiles([]string{onlineBoutiquePath()})
	// bb, err := loadFile(files[0])
	// if len(err) > 0 {
	// 	t.Errorf("%v", err)
	// }
	// for i := range bb {
	// 	t.Errorf("%s", bb[i].ToString())
	// }
}

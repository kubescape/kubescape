package resourcehandler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "examples/online-boutique/*")
}

func TestListFiles(t *testing.T) {

	filesPath := onlineBoutiquePath()

	files, errs := listFiles([]string{filesPath})
	assert.Equal(t, 0, len(errs))
	assert.Equal(t, 12, len(files))
}

func TestLoadFiles(t *testing.T) {
	files, _ := listFiles([]string{onlineBoutiquePath()})
	_, err := loadFiles(files)
	assert.Equal(t, 0, len(err))
}

func TestLoadFile(t *testing.T) {
	files, _ := listFiles([]string{strings.Replace(onlineBoutiquePath(), "*", "adservice.yaml", 1)})
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

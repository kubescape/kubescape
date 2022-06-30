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
			assert.Equal(t, "apps/v1//Deployment/adservice", getRelativePath(w[0].GetID()))
			assert.Equal(t, "/v1//Service/adservice", getRelativePath(w[1].GetID()))
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

func getRelativePath(p string) string {
	pp := strings.SplitAfter(p, "api=")
	return pp[1]
}

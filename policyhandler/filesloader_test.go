package policyhandler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/kubescape/cautils"
)

func combine(base, rel string) string {
	finalPath := []string{}
	sBase := strings.Split(base, "/")
	sRel := strings.Split(rel, "/")
	for i := range sBase {
		if cautils.StringInSlice(sRel, sBase[i]) != cautils.ValueNotFound {
			finalPath = append(finalPath, sRel...)
			break
		}
		finalPath = append(finalPath, sBase[i])
	}
	return fmt.Sprintf("/%s", filepath.Join(finalPath...))
}
func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return combine(o, "github.com/armosec/kubescape/examples/online-boutique/*")
}
func TestListFiles(t *testing.T) {
	files, errs := listFiles([]string{onlineBoutiquePath()})
	if len(errs) > 0 {
		t.Error(errs)
	}
	expected := 12
	if len(files) != expected {
		t.Errorf("wrong number of files, expected: %d, found: %d", expected, len(files))
	}
}

func TestLoadFiles(t *testing.T) {
	files, _ := listFiles([]string{onlineBoutiquePath()})
	loadFiles(files)
}

func TestLoadFile(t *testing.T) {
	files, _ := listFiles([]string{strings.Replace(onlineBoutiquePath(), "*", "bi-monitor.yaml", 1)})
	_, err := loadFile(files[0])
	if err != nil {
		t.Errorf("%v", err)
	}
}
func TestLoadResources(t *testing.T) {

	// k8sResources, err = policyHandler.loadResources(opaSessionObj.Frameworks, scanInfo)
	// files, _ := listFiles([]string{onlineBoutiquePath()})
	// bb, err := loadFile(files[0])
	// if len(err) > 0 {
	// 	t.Errorf("%v", err)
	// }
	// for i := range bb {
	// 	t.Errorf("%s", bb[i].ToString())
	// }
}

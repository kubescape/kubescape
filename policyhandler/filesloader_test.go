package policyhandler

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return path.Join(o+"/..", "examples/online-boutique/*")
}
func TestListFiles(t *testing.T) {
	workDir, err := os.Getwd()
	fmt.Printf("\n------------------\n%s,%v\n--------------\n", workDir, err)
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
	files, _ := listFiles([]string{strings.Replace(onlineBoutiquePath(), "*", "adservice.yaml", 1)})
	_, err := loadFile(files[0])
	if err != nil {
		t.Errorf("%v", err)
	}
}
func TestLoadResources(t *testing.T) {
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

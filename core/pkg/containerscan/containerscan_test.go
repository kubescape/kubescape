package containerscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/francoispqt/gojay"
)

func TestDecodeScanWIthDangearousArtifacts(t *testing.T) {
	rhs := &ScanResultReport{}
	er := gojay.NewDecoder(strings.NewReader(nginxScanJSON)).DecodeObject(rhs)
	if er != nil {
		t.Errorf("decode failed due to: %v", er.Error())
	}
	sumObj := rhs.Summarize()
	if sumObj.Registry != "" {
		t.Errorf("sumObj.Registry = %v", sumObj.Registry)
	}
	if sumObj.VersionImage != "nginx:1.18.0" {
		t.Errorf("sumObj.VersionImage = %v", sumObj.Registry)
	}
	if sumObj.ImgTag != "nginx:1.18.0" {
		t.Errorf("sumObj.ImgTag = %v", sumObj.ImgTag)
	}
	if sumObj.Status != "Success" {
		t.Errorf("sumObj.Status = %v", sumObj.Status)
	}
	if len(sumObj.ListOfDangerousArtifcats) != 3 {
		t.Errorf("sumObj.ListOfDangerousArtifcats = %v", sumObj.ListOfDangerousArtifcats)
	}
}

func TestUnmarshalScanReport(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	str1 := ds.AsFNVHash()
	rhs := &ScanResultReport{}

	bolB, _ := json.Marshal(ds)
	r := bytes.NewReader(bolB)

	er := gojay.NewDecoder(r).DecodeObject(rhs)
	if er != nil {
		t.Errorf("marshalling failed due to: %v", er.Error())
	}

	if rhs.AsFNVHash() != str1 {
		t.Errorf("marshalling failed different values after marshal:\nOriginal:\n%v\nParsed:\n%v\n\n===\n", string(bolB), rhs)
	}
}

func TestUnmarshalScanReport1(t *testing.T) {
	ds := Vulnerability{}
	if err := GenerateVulnerability(&ds); err != nil {
		t.Errorf("%v\n%v\n", ds, err)
	}
}

func TestGetByPkgNameSuccess(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	a := ds.Layers[0].GetFilesByPackage("coreutils")
	if a != nil {

		fmt.Printf("%+v\n", *a)
	}

}

func TestGetByPkgNameMissing(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	a := ds.Layers[0].GetFilesByPackage("s")
	if a != nil && len(*a) > 0 {
		t.Errorf("expected - no such package should be in that layer %v\n\n; found - %v", ds, a)
	}

}

func TestCalculateFixed(t *testing.T) {
	res := CalculateFixed([]FixedIn{{
		Name:    "",
		ImgTag:  "",
		Version: "",
	}})
	if 0 != res {
		t.Errorf("wrong fix status: %v", res)
	}
}

package containerscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/francoispqt/gojay"
)

func TestUnmarshalScanReport(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	str1 := ds.AsSha256()
	rhs := &ScanResultReport{}

	bolB, _ := json.Marshal(ds)
	r := bytes.NewReader(bolB)

	er := gojay.NewDecoder(r).DecodeObject(rhs)
	if er != nil {
		t.Errorf("marshalling failed due to: %v", er.Error())
	}

	if rhs.AsSha256() != str1 {
		t.Errorf("marshalling failed different values after marshal:\nOriginal:\n%v\nParsed:\n%v\n\n===\n", string(bolB), rhs)
	}
}

func TestConvScanReport2ESvul(t *testing.T) {
	// ds := GenerateContainerScanReportMock()
	// res := ds.ToFlatVulnerabilities()
	// vulsBytes, _ := json.Marshal(res)

	// summary := ds.Summerize()
	// summaryBytes, _ := json.Marshal(summary)

	// fmt.Printf("summary:\n%v\n\nvulnerabilities:\n%v\n\n", string(summaryBytes), string(vulsBytes))
	// t.Errorf("%v\n", string(vulsBytes))

}

func TestConvScanReport2ESWithNoVul(t *testing.T) {
	// ds := GenerateContainerScanReportNoVulMock()
	// res := ds.ToFlatVulnerabilities()
	// vulsBytes, _ := json.Marshal(res)

	// summary := ds.Summerize()
	// summaryBytes, _ := json.Marshal(summary)

	// fmt.Printf("summary:\n%v\n\nvulnerabilities:\n%v\n\n", string(summaryBytes), string(vulsBytes))
	// t.Errorf("%v\n", string(vulsBytes))

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
	if a != nil {

		t.Errorf("expected - no such package should be in that layer %v\n\n", ds)
	}

}

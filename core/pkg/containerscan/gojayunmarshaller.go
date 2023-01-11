package containerscan

import (
	"github.com/francoispqt/gojay"
)

/*
  responsible on fast unmarshaling of various COMMON containerscan structures and substructures

*/

// UnmarshalJSONObject - File inside a pkg
func (file *PackageFile) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "name":
		err = dec.String(&(file.Filename))
	}
	return err

}

func (files *PkgFiles) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := PackageFile{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*files = append(*files, lae)
	return nil
}

func (file *PackageFile) NKeys() int {
	return 0
}

// UnmarshalJSONObject--- Package
func (pkgnx *LinuxPackage) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "packageName":
		err = dec.String(&(pkgnx.PackageName))

	case "version":
		err = dec.String(&(pkgnx.PackageVersion))

	case "files":
		err = dec.Array(&(pkgnx.Files))
	}
	return err
}

func (file *LinuxPackage) NKeys() int {
	return 0
}

func (pkgs *LinuxPkgs) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := LinuxPackage{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*pkgs = append(*pkgs, lae)
	return nil
}

// --------Vul fixed in----------------------------------
func (fx *FixedIn) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "name":
		err = dec.String(&(fx.Name))

	case "imageTag":
		err = dec.String(&(fx.ImgTag))
	case "version":
		err = dec.String(&(fx.Version))
	}
	return err
}

func (t *VulFixes) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := FixedIn{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*t = append(*t, lae)
	return nil
}

func (file *FixedIn) NKeys() int {
	return 0
}

//------ VULNERABIlITy ---------------------

// Name               string      `json:"name"`
// ImgHash            string      `json:"imageHash"`
// ImgTag             string      `json:"imageTag",omitempty`
// RelatedPackageName string      `json:"packageName"`
// PackageVersion     string      `json:"packageVersion"`
// Link               string      `json:"link"`
// Description        string      `json:"description"`
// Severity           string      `json:"severity"`
// Metadata           interface{} `json:"metadata",omitempty`
// Fixes              VulFixes    `json:"fixedIn",omitempty`
// Relevancy          string      `json:"relevant"` // use the related enum

func (v *Vulnerability) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "name":
		err = dec.String(&(v.Name))

	case "imageTag":
		err = dec.String(&(v.ImgTag))
	case "imageHash":
		err = dec.String(&(v.ImgHash))

	case "packageName":
		err = dec.String(&(v.RelatedPackageName))

	case "packageVersion":
		err = dec.String(&(v.PackageVersion))

	case "link":
		err = dec.String(&(v.Link))

	case "description":
		err = dec.String(&(v.Description))

	case "severity":
		err = dec.String(&(v.Severity))

	case "relevant":
		err = dec.String(&(v.Relevancy))

	case "fixedIn":
		err = dec.Array(&(v.Fixes))

	case "metadata":
		err = dec.Interface(&(v.Metadata))
	}

	return err
}

func (t *VulnerabilitiesList) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := Vulnerability{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*t = append(*t, lae)
	return nil
}

func (v *Vulnerability) NKeys() int {
	return 0
}

//---------Layer Object----------------------------------
// type ScanResultLayer struct {
// 	LayerHash       string          `json:layerHash`
// 	Vulnerabilities []Vulnerability `json:vulnerabilities`
// 	Packages        []LinuxPackage  `json:packageToFile`
// }

func (scan *ScanResultLayer) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	// case "timestamp":
	// err = dec.Time(&(reporter.Timestamp), time.RFC3339)
	// reporter.Timestamp = reporter.Timestamp.Local()
	case "layerHash":
		err = dec.String(&(scan.LayerHash))

	case "parentLayerHash":
		err = dec.String(&(scan.ParentLayerHash))

	case "vulnerabilities":
		err = dec.Array(&(scan.Vulnerabilities))
	case "packageToFile":
		err = dec.Array(&(scan.Packages))
	}
	return err
}

func (t *LayersList) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := ScanResultLayer{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*t = append(*t, lae)
	return nil
}

func (scan *ScanResultLayer) NKeys() int {
	return 0
}

//---------------------SCAN RESULT--------------------------------------------------------------------------

// type ScanResultReport struct {
// 	CustomerGUID string            `json:customerGuid`
// 	ImgTag       string            `json:imageTag,omitempty`
// 	ImgHash      string            `json:imageHash`
// 	WLID         string            `json:wlid`
// 	Timestamp    int               `json:customerGuid`
// 	Layers       []ScanResultLayer `json:layers`
// ContainerName
// }

func (scan *ScanResultReport) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	// case "timestamp":
	// err = dec.Time(&(reporter.Timestamp), time.RFC3339)
	// reporter.Timestamp = reporter.Timestamp.Local()
	case "customerGUID":
		err = dec.String(&(scan.CustomerGUID))
	case "imageTag":
		err = dec.String(&(scan.ImgTag))
	case "imageHash":
		err = dec.String(&(scan.ImgHash))
	case "wlid":
		err = dec.String(&(scan.WLID))
	case "containerName":
		err = dec.String(&(scan.ContainerName))
	case "timestamp":
		err = dec.Int64(&(scan.Timestamp))
	case "layers":
		err = dec.Array(&(scan.Layers))

	case "listOfDangerousArtifcats":
		err = dec.SliceString(&(scan.ListOfDangerousArtifcats))

	}
	return err
}

func (scan *ScanResultReport) NKeys() int {
	return 0
}

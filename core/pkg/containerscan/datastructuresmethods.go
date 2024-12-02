package containerscan

import (
	"strings"

	"github.com/armosec/armoapi-go/identifiers"
)

// GetPackagesNames retrieves the names of all the packages stored in the Packages field of the ScanResultLayer object and returns them as a slice of strings.
func (layer *ScanResultLayer) GetPackagesNames() []string {
	pkgsNames := []string{}
	for _, pkg := range layer.Packages {
		pkgsNames = append(pkgsNames, pkg.PackageName)
	}
	return pkgsNames
}

// GetDesignatorsNContext retrieves the designators and context information from the ScanResultReport object and returns them as a pair of objects.
func (scanresult *ScanResultReport) GetDesignatorsNContext() (*identifiers.PortalDesignator, []identifiers.ArmoContext) {
	designatorsObj := identifiers.AttributesDesignatorsFromWLID(scanresult.WLID)
	designatorsObj.Attributes["containerName"] = scanresult.ContainerName
	designatorsObj.Attributes["customerGUID"] = scanresult.CustomerGUID
	contextObj := identifiers.DesignatorToArmoContext(designatorsObj, "designators")
	return designatorsObj, contextObj
}

// Validate checks if the scan result report is valid.
func (scanresult *ScanResultReport) Validate() bool {
	if scanresult.CustomerGUID == "" || (scanresult.ImgHash == "" && scanresult.ImgTag == "") || scanresult.Timestamp <= 0 {
		return false
	}

	//TODO validate layers & vuls

	return true
}

// IsRCE checks if a vulnerability description contains any keywords related to remote code execution (RCE) or arbitrary code injection.
func (v *Vulnerability) IsRCE() bool {
	desc := strings.ToLower(v.Description)

	isRCE := strings.Contains(v.Description, "RCE")

	return isRCE || strings.Contains(desc, "remote code execution") || strings.Contains(desc, "remote command execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "code execution") || strings.Contains(desc, "code injection") || strings.Contains(desc, "command injection") || strings.Contains(desc, "inject arbitrary commands")
}

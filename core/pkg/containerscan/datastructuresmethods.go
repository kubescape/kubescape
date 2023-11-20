package containerscan

import (
	"strings"

	"github.com/armosec/armoapi-go/identifiers"
)

// GetFilesByPackage retrieves a list of files associated with a specific package name from the Packages field of the ScanResultLayer object.
//
// Inputs:
// - pkgname (string): The name of the package to retrieve files for.
//
// Flow:
// 1. Iterate over each package in the Packages field of the ScanResultLayer object.
// 2. Check if the PackageName field of the current package matches the provided pkgname.
// 3. If a match is found, return a pointer to the Files field of the package.
// 4. If no match is found, return an empty PkgFiles object.
//
// Outputs:
// - files (*PkgFiles): A pointer to the list of files associated with the specified package name. If no match is found, an empty PkgFiles object is returned.
func (layer *ScanResultLayer) GetFilesByPackage(pkgname string) (files *PkgFiles) {
	for _, pkg := range layer.Packages {
		if pkg.PackageName == pkgname {
			return &pkg.Files
		}
	}

	return &PkgFiles{}
}

func (layer *ScanResultLayer) GetPackagesNames() []string {
	pkgsNames := []string{}
	for _, pkg := range layer.Packages {
		pkgsNames = append(pkgsNames, pkg.PackageName)
	}
	return pkgsNames
}

func (scanresult *ScanResultReport) GetDesignatorsNContext() (*identifiers.PortalDesignator, []identifiers.ArmoContext) {
	designatorsObj := identifiers.AttributesDesignatorsFromWLID(scanresult.WLID)
	designatorsObj.Attributes["containerName"] = scanresult.ContainerName
	designatorsObj.Attributes["customerGUID"] = scanresult.CustomerGUID
	contextObj := identifiers.DesignatorToArmoContext(designatorsObj, "designators")
	return designatorsObj, contextObj
}

func (scanresult *ScanResultReport) Validate() bool {
	if scanresult.CustomerGUID == "" || (scanresult.ImgHash == "" && scanresult.ImgTag == "") || scanresult.Timestamp <= 0 {
		return false
	}

	//TODO validate layers & vuls

	return true
}

func (v *Vulnerability) IsRCE() bool {
	desc := strings.ToLower(v.Description)

	isRCE := strings.Contains(v.Description, "RCE")

	return isRCE || strings.Contains(desc, "remote code execution") || strings.Contains(desc, "remote command execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "code execution") || strings.Contains(desc, "code injection") || strings.Contains(desc, "command injection") || strings.Contains(desc, "inject arbitrary commands")
}

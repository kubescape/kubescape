package containerscan

import (
	"regexp"
	"strings"

	"github.com/armosec/armoapi-go/identifiers"
)

// rceAcronymRe matches the standalone "RCE" acronym case-insensitively. The
// word boundaries are what keep it from matching the substring inside unrelated
// words such as "source", "force" or "resource", which would otherwise flood
// the RCE tally with false positives on almost every vulnerability description.
var rceAcronymRe = regexp.MustCompile(`(?i)\brce\b`)

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

	if scanresult.Layers == nil {
		return false
	}

	type vulnerabilityKey struct {
		Name               string
		RelatedPackageName string
		PackageVersion     string
	}
	layerHashes := make(map[string]bool)

	for _, layer := range scanresult.Layers {
		if layer.LayerHash != "" {
			if layerHashes[layer.LayerHash] {
				return false
			}
			layerHashes[layer.LayerHash] = true
		}

		vulnKeys := make(map[vulnerabilityKey]bool)

		for _, vul := range layer.Vulnerabilities {
			if vul.Name == "" {
				return false
			}
			key := vulnerabilityKey{
				Name:               vul.Name,
				RelatedPackageName: vul.RelatedPackageName,
				PackageVersion:     vul.PackageVersion,
			}
			if vulnKeys[key] {
				return false
			}
			vulnKeys[key] = true
		}
	}

	return true
}

// IsRCE checks if a vulnerability description contains any keywords related to remote code execution (RCE) or arbitrary code injection.
func (v *Vulnerability) IsRCE() bool {
	desc := strings.ToLower(v.Description)

	isRCE := rceAcronymRe.MatchString(v.Description)

	return isRCE || strings.Contains(desc, "remote code execution") || strings.Contains(desc, "remote command execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "code execution") || strings.Contains(desc, "code injection") || strings.Contains(desc, "command injection") || strings.Contains(desc, "inject arbitrary commands")
}

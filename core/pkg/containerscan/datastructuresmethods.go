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

// vulnKey identifies a vulnerability uniquely inside a layer for duplicate detection.
type vulnKey struct {
	Name, RelatedPackageName, PackageVersion string
}

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

	seenHashes := make(map[string]struct{}, len(scanresult.Layers))
	for i := range scanresult.Layers {
		layer := &scanresult.Layers[i]
		if layer.LayerHash == "" {
			return false
		}
		if _, exists := seenHashes[layer.LayerHash]; exists {
			return false
		}
		seenHashes[layer.LayerHash] = struct{}{}

		seenVulns := make(map[vulnKey]struct{}, len(layer.Vulnerabilities))
		for j := range layer.Vulnerabilities {
			v := &layer.Vulnerabilities[j]
			if v.Name == "" {
				return false
			}
			key := vulnKey{v.Name, v.RelatedPackageName, v.PackageVersion}
			if _, exists := seenVulns[key]; exists {
				return false
			}
			seenVulns[key] = struct{}{}
		}
	}

	return true
}

// IsRCE checks if a vulnerability description contains any keywords related to remote code execution (RCE) or arbitrary code injection.
func (v *Vulnerability) IsRCE() bool {
	if v == nil {
		return false
	}

	desc := strings.ToLower(v.Description)

	isRCE := rceAcronymRe.MatchString(v.Description)

	return isRCE || strings.Contains(desc, "remote code execution") || strings.Contains(desc, "remote command execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "code execution") || strings.Contains(desc, "code injection") || strings.Contains(desc, "command injection") || strings.Contains(desc, "inject arbitrary commands")
}

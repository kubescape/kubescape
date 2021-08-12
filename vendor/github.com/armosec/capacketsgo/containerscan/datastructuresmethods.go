package containerscan

import "strings"

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

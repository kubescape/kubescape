package containerscan

import (
	"bytes"
	"math/rand"
	"time"

	"github.com/francoispqt/gojay"
)

// GenerateContainerScanReportMock - generate a scan result
func GenerateContainerScanReportMock() ScanResultReport {
	ds := ScanResultReport{
		WLID:         "wlid://cluster-k8s-geriatrix-k8s-demo3/namespace-whisky-app/deployment-whisky4all-shipping",
		CustomerGUID: "1231bcb1-49ce-4a67-bdd3-5da7a393ae08",
		ImgTag:       "dreg.armo.cloud:443/demoservice:v16",
		ImgHash:      "docker-pullable://dreg.armo.cloud:443/demoservice@sha256:754f3cfca915a07ed10655a301dd7a8dc5526a06f9bd06e7c932f4d4108a8296",
		Timestamp:    time.Now().UnixNano(),
	}

	ds.Layers = make(LayersList, 0)
	layer := ScanResultLayer{}
	GenerateContainerScanLayer(&layer)
	ds.Layers = append(ds.Layers, layer)
	return ds
}

// GenerateContainerScanReportMock - generate a scan result
func GenerateContainerScanReportNoVulMock() ScanResultReport {
	ds := ScanResultReport{
		WLID:          "wlid://cluster-k8s-geriatrix-k8s-demo3/namespace-whisky-app/deployment-whisky4all-shipping",
		CustomerGUID:  "1231bcb1-49ce-4a67-bdd3-5da7a393ae08",
		ImgTag:        "dreg.armo.cloud:443/demoservice:v16",
		ImgHash:       "docker-pullable://dreg.armo.cloud:443/demoservice@sha256:754f3cfca915a07ed10655a301dd7a8dc5526a06f9bd06e7c932f4d4108a8296",
		Timestamp:     time.Now().UnixNano(),
		ContainerName: "shipping",
	}

	ds.Layers = make(LayersList, 0)
	layer := ScanResultLayer{LayerHash: "aaa"}
	ds.Layers = append(ds.Layers, layer)
	return ds
}

var hash = []rune("abcdef0123456789")
var nums = []rune("0123456789")

func randSeq(n int, bank []rune) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, n)
	for i := range b {
		b[i] = bank[rand.Intn(len(bank))] //nolint:gosec
	}
	return string(b)
}

// GenerateContainerScanLayer - generate a layer with random vuls
func GenerateContainerScanLayer(layer *ScanResultLayer) {
	layer.LayerHash = randSeq(32, hash)
	layer.Vulnerabilities = make(VulnerabilitiesList, 0)
	layer.Packages = make(LinuxPkgs, 0)
	vuls := rand.Intn(10) + 1 //nolint:gosec

	for i := 0; i < vuls; i++ {
		v := Vulnerability{}
		GenerateVulnerability(&v)
		layer.Vulnerabilities = append(layer.Vulnerabilities, v)
	}

	pkg := LinuxPackage{PackageName: "coreutils"}
	pkg.Files = make(PkgFiles, 0)
	pf := PackageFile{Filename: "aa"}
	pkg.Files = append(pkg.Files, pf)
	layer.Packages = append(layer.Packages, pkg)
}

// GenerateVulnerability - generate a vul (just diff "cve"'s)
func GenerateVulnerability(v *Vulnerability) error {
	baseVul := " { \"name\": \"CVE-2014-9471\", \"imageTag\": \"debian:8\", \"link\": \"https://security-tracker.debian.org/tracker/CVE-2014-9471\", \"description\": \"The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the sdf\", \"severity\": \"Low\", \"metadata\": { \"NVD\": { \"CVSSv2\": { \"Score\": 7.5, \"Vectors\": \"AV:N/AC:L/Au:N/C:P/I:P\" } } }, \"fixedIn\": [ { \"name\": \"coreutils\", \"imageTag\": \"debian:8\", \"version\": \"8.23-1\" } ] }"
	b := []byte(baseVul)
	r := bytes.NewReader(b)
	er := gojay.NewDecoder(r).DecodeObject(v)
	v.RelatedPackageName = "coreutils"
	v.Severity = HighSeverity
	v.Relevancy = Irelevant
	v.Name = "CVE-" + randSeq(4, nums) + "-" + randSeq(4, nums)
	return er

}

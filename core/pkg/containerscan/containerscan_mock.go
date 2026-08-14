package containerscan

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/francoispqt/gojay"
)

// randIntn returns a uniform random value in [0, n) using a cryptographically
// secure source. Falls back to 0 only if the source is unavailable.
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

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

// GenerateContainerScanReportNoVulMock - generate a scan result
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
	b := make([]rune, n)
	for i := range b {
		b[i] = bank[randIntn(len(bank))]
	}
	return string(b)
}

// GenerateContainerScanLayer - generate a layer with random vuls
func GenerateContainerScanLayer(layer *ScanResultLayer) {
	layer.LayerHash = randSeq(32, hash)
	layer.Vulnerabilities = make(VulnerabilitiesList, 0)
	layer.Packages = make(LinuxPkgs, 0)
	vuls := randIntn(10) + 1

	for range vuls {
		v := Vulnerability{}
		_ = GenerateVulnerability(&v) // #nosec G104 -- mock generator; the error is irrelevant for synthetic data
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

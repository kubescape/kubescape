package containerimages

import (
	"fmt"
	"testing"
)

func TestSum(t *testing.T) {
	credentials := make(map[string]string)
	credentials["clientId"] = "378754de-e70d-4c33-a475-1818d296ff26"
	credentials["accessKey"] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	credentials["accountId"] = "2ce5daf4-e28d-4e6e-a239-03fda048070b"
	adaptor, err := CreateArmoAdaptor("armoui-dev.eudev3.cyberarmorsoft.com", credentials)
	if err != nil {
		t.Fatalf("Cannot initialize adaptor: %s", err)
	}
	err = adaptor.Login()
	if err != nil {
		t.Fatalf("Cannot login with adaptor: %s", err)
	}
	//fmt.Printf("Login successful: %s\n", adaptor.feToken.Token)

	imageVulnerabilityReport, err := adaptor.GetImageVulnerabilty(&ContainerImageIdentifier{Tag: "gke.gcr.io/gcp-compute-persistent-disk-csi-driver:v1.3.4-gke.0"})
	if err != nil {
		t.Fatalf("Cannot get vulnerabilities: %s", err)
	}
	for _, vulnerability := range imageVulnerabilityReport.Vulnerabilities {
		fmt.Printf("%s: %s\n", vulnerability.Name, vulnerability.Description)
	}
}

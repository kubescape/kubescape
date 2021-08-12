package ocimage

// import (
// 	"fmt"
// 	"io"
// 	"os"
// 	"testing"
// )

// func base(img, usr, pass string) (*OCImage, string, error) {
// 	baseURL := "http://10.107.26.199:8080"
// 	oci := MakeOCImage(baseURL)
// 	imgid, err := oci.GetImage(img, usr, pass)

// 	return oci, imgid, err
// }
// func TestGetSingleFile(t *testing.T) {
// 	fmt.Printf("do nothing")
// 	oci, imgid, err := base("nginx:latest", "", "")
// 	if err != nil {
// 		t.Errorf("can't get image ")
// 	}
// 	os, s, err := oci.GetSingleFile(imgid, "/etc/os-release", true)
// 	if err != nil {
// 		t.Errorf("couldnt get file %s", err.Error())
// 	}
// 	fmt.Printf("file content: %s\n%s\n", string(os), s)
// 	t.Errorf("f")
// }

// func TestManifest(t *testing.T) {
// 	fmt.Printf("do nothing")
// 	oci, imgid, err := base("nginx:latest", "", "")
// 	if err != nil {
// 		t.Errorf("can't get image ")
// 	}
// 	manifest, err := oci.GetManifest(imgid)
// 	if err != nil {
// 		t.Errorf("couldnt get file %s", err.Error())
// 	}
// 	fmt.Printf("manifest content: %v\n\n", manifest)
// 	t.Errorf("f")
// }

// //gets 404 when no files are found
// func TestMultipleFilesNonExisting(t *testing.T) {
// 	fmt.Printf("do nothing")
// 	oci, imgid, err := base("nginx:latest", "", "")
// 	if err != nil {
// 		t.Errorf("can't get image ")
// 	}
// 	filestar, err := oci.GetMultipleFiles(imgid, []string{"/ethhhc/os-release", "ngjjjinx"}, true, false)
// 	if err != nil {
// 		t.Errorf("couldnt get file %s", err.Error())
// 		return
// 	}

// 	for {
// 		tarHdr, err := filestar.Next()
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			t.Errorf("error: %s", err.Error())
// 			continue
// 		}

// 		fmt.Printf("Contents of %s:\n", tarHdr.Name)
// 		if _, err := io.Copy(os.Stdout, filestar); err != nil {
// 			t.Errorf("error: %s", err.Error())
// 		}
// 		fmt.Printf("%v\n", tarHdr)
// 	}

// 	t.Errorf("f")
// }

// //gets Symlink mapper as usual (missing files has no key)
// func TestMultipleFilesPartialExisting(t *testing.T) {
// 	fmt.Printf("do nothing")
// 	oci, imgid, err := base("nginx:latest", "", "")
// 	if err != nil {
// 		t.Errorf("can't get image ")
// 	}
// 	filestar, err := oci.GetMultipleFiles(imgid, []string{"/etc/os-release", "ngjjjinx"}, true, false)
// 	if err != nil {
// 		t.Errorf("couldnt get file %s", err.Error())
// 		return
// 	}

// 	for {
// 		tarHdr, err := filestar.Next()
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			t.Errorf("error: %s", err.Error())
// 			continue
// 		}

// 		fmt.Printf("Contents of %s:\n", tarHdr.Name)
// 		if _, err := io.Copy(os.Stdout, filestar); err != nil {
// 			t.Errorf("error: %s", err.Error())
// 		}
// 		fmt.Printf("%v\n", tarHdr)
// 	}

// 	t.Errorf("f")
// }

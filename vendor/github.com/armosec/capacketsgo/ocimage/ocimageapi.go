package ocimage

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

var MAX_RETRIES int = 3

// IOCImage - ocimage interface - https://asterix.cyberarmor.io/cyberarmor/ocimage
type IOCImage interface {
	GetImage(imageTag, user, password string) (string, error)
	GetSingleFile(fileName string, followSymLink bool) ([]byte, string, error)
	GetMultipleFiles(fileNames []string, followSymLink, doesExist bool) ([]byte, error)
	GetClient() *http.Client
	FileList(imageid string, dir string, from int, to int, recursive bool, noDir bool) ([]FileMetadata, error)
	Describe(imageID string) (*ImageMetadata, error)
}

// OCImage - structure, holds url and api version
type OCImage struct {
	url    string
	apiVer string
	client *http.Client
}

func (oci *OCImage) GetClient() *http.Client {
	return oci.client
}

// Init - init
func MakeOCImage(ociURL string) *OCImage {
	oci := &OCImage{url: ociURL, apiVer: "v1", client: &http.Client{}}

	return oci
}

func (oci *OCImage) GetManifest(imageid string) (*OciImageManifest, error) {

	newurl := fmt.Sprintf("%s/%s/images/id/%s/manifest", oci.url, oci.apiVer, imageid)
	req, _ := http.NewRequest("GET", newurl, nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := oci.GetClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting manifest for imageid: %s failed due to: %s", imageid, err.Error())
	}

	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("getting manifest for imageid: %s failed due to: status code %v %v", imageid, resp.StatusCode, resp.Status)
	}
	jsonRaw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	manifest := OciImageManifest{}
	if err := json.Unmarshal(jsonRaw, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// GetImage -
func (oci *OCImage) GetImage(imageTag, user, password string) (string, error) {
	newurl := oci.url + "/" + oci.apiVer + "/images/id"
	values := map[string]string{"image": imageTag}

	if len(user) != 0 && len(password) != 0 {
		values["username"] = user
		values["password"] = password
	}

	jsonValue, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("failed to marshal getImage request, reason: %s", err.Error())
	}
	glog.Infof("OCI GetImage, url: '%s'", newurl)
	for i := 0; i < MAX_RETRIES; i++ {
		resp, err := http.Post(newurl, "application/json", bytes.NewBuffer(jsonValue))
		if err != nil {
			glog.Infof("In GetImage oci, url: '%s', failed. retry: %d, reason: %s", newurl, i, err.Error())
			time.Sleep(1 * time.Second)
			continue
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		bodyString := string(body)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return bodyString, nil
		} else {
			glog.Errorf("requesting: %v - will retry error (%s): %s", newurl, resp.Status, bodyString)
		}
	}

	return "", fmt.Errorf("request '%s' failed, reason: max retries exceeded", newurl)
}

// FileList - ls = the containerized version
func (oci *OCImage) FileList(imageid string, dir string, from int, to int, recursive bool, noDir bool) ([]FileMetadata, error) {
	newurl := oci.url + "/" + oci.apiVer + "/images/id/" + imageid + "/list"
	fmt.Printf("%v %v %v %v %v %v $v", newurl, dir, from, to, recursive, noDir)
	var slashwrist []FileMetadata

	req, _ := http.NewRequest("GET", newurl, nil)
	req.Header.Add("Accept", "application/json")
	q := req.URL.Query()
	if len(dir) > 0 {
		q.Add("dir", dir)
	}
	if from < to || to == -1 {
		fromstr := strconv.Itoa(from)
		tostr := strconv.Itoa(to)
		q.Add("from", fromstr)
		q.Add("to", tostr)
	}

	q.Add("recursive", strconv.FormatBool(recursive))
	q.Add("no_dir", strconv.FormatBool(noDir))
	req.URL.RawQuery = q.Encode()

	glog.Infof("OCI FileList, url: '%s'", req.URL.String())

	for i := 0; i < MAX_RETRIES; i++ {
		resp, err := oci.GetClient().Do(req)

		if err != nil {
			glog.Errorf("requesting: %v - will retry error: %v", newurl, err.Error())
		}
		defer resp.Body.Close()
		if respBody, err := ioutil.ReadAll(resp.Body); err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if err := json.Unmarshal(respBody, &slashwrist); err != nil {
					return slashwrist, fmt.Errorf("failed to marshal fileList response, reason: %s", err.Error())
				}
				return slashwrist, nil
			} else {
				glog.Errorf("requesting: %v - will retry error (%s): %s", newurl, resp.Status, respBody)
			}
		} else {
			glog.Errorf("requesting: %v - will retry error: %v", newurl, err.Error())
		}

	}
	return nil, fmt.Errorf("request '%s' failed, reason: max retries exceeded", newurl)

}

// Describe -
func (oci *OCImage) Describe(imageid string) (ImageMetadata, error) {
	newurl := oci.url + "/" + oci.apiVer + "/images/id/" + imageid
	glog.Infof("OCI Describe, url: '%s'", newurl)

	var slashwrist ImageMetadata

	req, _ := http.NewRequest("GET", newurl, nil)
	req.Header.Add("Accept", "application/json")
	for i := 0; i < MAX_RETRIES; i++ {
		resp, err := oci.GetClient().Do(req)
		if err == nil {
			defer resp.Body.Close()
			if respBody, err := ioutil.ReadAll(resp.Body); err == nil {
				if err := json.Unmarshal(respBody, &slashwrist); err != nil {
					return slashwrist, fmt.Errorf("failed to unmarshal describe response, reason: %s", err.Error())
				}
				return slashwrist, nil
			} else {
				glog.Errorf("requesting: %s - will retry error: %v", newurl, err.Error())
			}
		} else {
			glog.Errorf("requesting: %s - will retry error: %v", newurl, err.Error())
		}
	}

	return slashwrist, fmt.Errorf("request '%s' failed, reason: max retries exceeded", newurl)

}

func (oci *OCImage) GetMultipleFiles(imageid string, fileNames []string, followSymLink, doesExist bool) (*tar.Reader, error) {

	if len(fileNames) == 0 || len(imageid) == 0 {
		return nil, fmt.Errorf("bad usage: u must specify non-empty filelist and imageid ")
	}
	newurl := oci.url + "/" + oci.apiVer + "/images/id/" + imageid + "/files"

	req, err := http.NewRequest("GET", newurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "octet-stream")

	q := req.URL.Query()
	q.Add("followSymLink", strconv.FormatBool(followSymLink))
	q.Add("doesExist", strconv.FormatBool(doesExist))
	for _, filename := range fileNames {
		q.Add("file", filename)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := oci.GetClient().Do(req)
	if err != nil {
		err = fmt.Errorf("error requesting file '%s' from server reason: %s", fileNames, err.Error())
		glog.Errorf(err.Error())
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {

		return nil, fmt.Errorf("error has occurred: " + resp.Status)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error: failed to read imageid %s files requested %v due to %s", imageid, fileNames, err.Error())
	}
	reader := bytes.NewReader(data)
	filestar := tar.NewReader(reader)

	return filestar, nil
}

// GetFile -
func (oci *OCImage) GetSingleFile(imageid string, filepath string, followSymLink bool) ([]byte, string, error) {
	newurl := oci.url + "/" + oci.apiVer + "/images/id/" + imageid + "/files/" + filepath

	glog.Infof("Requesting from OCI: '%s'", newurl)
	var slashwrist []byte

	client := &http.Client{}

	req, err := http.NewRequest("GET", newurl, nil)
	if err != nil {
		return slashwrist, "", err
	}
	req.Header.Add("Accept", "octet-stream")

	q := req.URL.Query()
	q.Add("followSymLink", strconv.FormatBool(followSymLink))
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("error requesting file '%s' from server reason: %s", filepath, err.Error())
		glog.Errorf(err.Error())
		return slashwrist, "", err
	}
	if resp.StatusCode != http.StatusOK {

		return slashwrist, "error has occurred: " + resp.Status, fmt.Errorf("error has occurred: " + resp.Status)
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)

	return respBody, "success", err

}

// GetFile -
func (oci *OCImage) GetFileWithRetries(imageid string, filepath string, followSymLink bool) ([]byte, string, error) {
	retry := 0
	for {
		respBody, status, err := oci.GetSingleFile(imageid, filepath, followSymLink)
		if err != nil && strings.Contains(err.Error(), "EOF") && retry < MAX_RETRIES {
			glog.Warningf("Request: '%s', received 'EOF'. Retying", filepath)
			retry++
			time.Sleep(1 * time.Second)
		} else {
			return respBody, status, err
		}

	}
}

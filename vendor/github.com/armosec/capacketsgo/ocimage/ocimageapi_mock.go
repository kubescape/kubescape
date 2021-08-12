package ocimage

import (
	"encoding/json"
	"strings"
)

// import "encoding/json"

// OCImageMock -
type OCImageMock struct {
}

// GetImage -
func (ocim *OCImageMock) GetImage(imageTag, user, password string) (string, error) {
	return "5ac6aae02c212cafb36e853dcfe366bac4b1c1097fe8c10c923842f09c8bf7e4", nil

}

// // FileList - mock
func (ocim *OCImageMock) FileList(imageid string, dir string, from int, to int, recursive bool, noDir bool) ([]FileMetadata, error) {
	listOfFiles := []FileMetadata{}
	list := `[{"isSymbolicLink":false,"layer":"sha256:f010348cae17a90a12165366416cb15c9606ea63a3735f9d967b843d33865f31","link":"","name":"etc/nginx","path":"etc/nginx","permissions":"0o40755"},{"isSymbolicLink":false,"layer":"sha256:1ce95ec4847ff9d80847f0a1836135255742c2160bc4ba52c829dfbc68a93291","link":"","name":"etc/apk","path":"etc/apk","permissions":"0o40755"},{"isSymbolicLink":false,"layer":"sha256:62bed320c887a0e141341a598b3a754c288bc91a15e66c7e1d10a941f63bc0c1","link":"","name":"etc/supervisor.d","path":"etc/supervisor.d","permissions":"0o40755"}]`
	json.Unmarshal([]byte(list), &listOfFiles)
	return listOfFiles, nil
}

// // Describe -
func (ocim *OCImageMock) Describe(imageID string) (*ImageMetadata, error) {
	imageData := &ImageMetadata{}
	id := `{"architecture":"amd64","info":{"architecture":"amd64","config":{"ArgsEscaped":true,"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["/nginx"],"Domainname":"","Entrypoint":["/entrypoint.sh"],"Env":["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D","PYTHON_VERSION=3.6.5","PYTHON_PIP_VERSION=10.0.1","NGINX_VERSION=1.13.8","UWSGI_INI=/app/uwsgi.ini","UWSGI_CHEAPER=2","UWSGI_PROCESSES=16","NGINX_MAX_UPLOAD=0","NGINX_WORKER_PROCESSES=1","LISTEN_PORT=80","STATIC_URL=/static","STATIC_PATH=/app/static","STATIC_INDEX=0","PYTHONPATH=/app"],"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Hostname":"d98c43c06009","Image":"sha256:66531c940f46ea26a1db3c63583058b56f97b2e85f83feaa2a41b8e58e702419","Labels":{"maintainer":"Sebastian Ramirez <tiangolo@gmail.com>"},"OnBuild":[],"OpenStdin":false,"StdinOnce":false,"Tty":false,"User":"","Volumes":null,"WorkingDir":"/app"},"container":"8086c88edd59db391d40b0bd6463e6521ccf6e7ec97ccb4aa236d6612cebec1c","container_config":{"ArgsEscaped":true,"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["/bin/sh","-c","#(nop) COPY file:3f7d33a0228dc7f9feb6b386b9cac9f2730d691a447399a8c1ae2755e8477312 in /app/. "],"Domainname":"","Entrypoint":["/entrypoint.sh"],"Env":["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D","PYTHON_VERSION=3.6.5","PYTHON_PIP_VERSION=10.0.1","NGINX_VERSION=1.13.8","UWSGI_INI=/app/uwsgi.ini","UWSGI_CHEAPER=2","UWSGI_PROCESSES=16","NGINX_MAX_UPLOAD=0","NGINX_WORKER_PROCESSES=1","LISTEN_PORT=80","STATIC_URL=/static","STATIC_PATH=/app/static","STATIC_INDEX=0","PYTHONPATH=/app"],"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Hostname":"d98c43c06009","Image":"sha256:66531c940f46ea26a1db3c63583058b56f97b2e85f83feaa2a41b8e58e702419","Labels":{"maintainer":"Sebastian Ramirez <tiangolo@gmail.com>"},"OnBuild":[],"OpenStdin":false,"StdinOnce":false,"Tty":false,"User":"","Volumes":null,"WorkingDir":"/app"},"created":"2018-11-25T11:37:00.787977594Z","docker_version":"1.13.1","id":"4944f7cd6bdbabd69dfde3efe800f996a43a373db9a5a07824ee30b908f61bfb","os":"linux","parent":"080f106513ef7ac9a5375e22ae6e56584bf745e401fbb21dd54d7fcf22ef8570"},"name":"signer","schemaVersion":1,"signatures":[{"header":{"alg":"ES256","jwk":{"crv":"P-256","kid":"W5FE:S6CL:XC37:EVE5:HSZD:OODU:4KWZ:WEIM:RRNN:MKXO:IO6H:Y7N4","kty":"EC","x":"DpcaARFTpltBfJ4cAGdE9Gp9AO2dEogJRBsWC9A2My0","y":"OTD5zOUaIa1bldgfGhVSpve-Urfxcpl1QS35hSBQoXQ"}},"protected":"eyJmb3JtYXRMZW5ndGgiOjM5MTc4LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMjAtMDUtMTRUMDc6NTc6MTBaIn0","signature":"hWCo_ezuNNz4e3M1opkK4Mrh9XcQE3K69ppL9_aboFaIPDzJWCZh2yt4zX4rM3dT3-2lLYuurFqgvw4dwLaJ4g"}],"tag":"70"}`
	json.Unmarshal([]byte(id), imageData)
	return imageData, nil
}

func (ocim *OCImageMock) GetSingleFile(fileName string, followSymLink bool) ([]byte, string, error) {
	if strings.Contains(fileName, "-release") {
		os := []byte("PRETTY_NAME=\"Debian GNU/Linux 10 (buster)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"10\"\nVERSION=\"10 (buster)\"\nVERSION_CODENAME=buster\nID=debian\nHOME_URL=\"https://www.debian.org/\"\nSUPPORT_URL=\"https://www.debian.org/support\"\nBUG_REPORT_URL=\"https://bugs.debian.org/\"\n")

		return os, "os", nil
	}

	nginx := []byte("# Defaults for nginx initscript\n# sourced by /etc/init.d/nginx\n\n# Additional options that are passed to nginx\nDAEMON_ARGS=\"\"\n")
	return nginx, "nginxscript", nil
}

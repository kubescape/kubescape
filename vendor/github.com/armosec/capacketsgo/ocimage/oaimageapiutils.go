package ocimage

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
)

// URLEncoder encode url
func URLEncoder(oldURL string) string {
	fullURL := strings.Split(oldURL, "?")
	baseURL, err := url.Parse(fullURL[0])
	if err != nil {
		return ""
	}

	// Prepare Query Parameters
	if len(fullURL) > 1 {
		params := url.Values{}
		queryParams := strings.Split(fullURL[1], "&")
		for _, i := range queryParams {
			queryParam := strings.Split(i, "=")
			val := ""
			if len(queryParam) > 1 {
				val = queryParam[1]
			}
			params.Add(queryParam[0], val)
		}
		baseURL.RawQuery = params.Encode()
	}

	return baseURL.String()
}

// GetSecuredImageID - gets imagename+tag or with full repo, secrets map and returns the imageid
func (ocimg *OCImage) GetSecuredImageID(imageName string, secrets map[string]types.AuthConfig) (string, error) {
	glog.Infof("trying to get Img: %v using secrets", imageName)

	for secretName, regAuth := range secrets {
		// If server address is known, then try pulling image based on sever address, otherwise try using all secretes
		if regAuth.ServerAddress == "" || strings.HasPrefix(imageName, regAuth.ServerAddress) {
			glog.Infof("Pulling image '%s' using '%s' secret", imageName, secretName)

			// Pulling image with credentials
			imageid, err := ocimg.GetImage(imageName, regAuth.Username, regAuth.Password)
			if err == nil {
				glog.Infof("Pulling image '%s' using secret succeeded, image id: %s", imageName, imageid)
				return imageid, nil
			}

		}
	}

	return "", fmt.Errorf("failed to pull image '%s' using secrets, secrets: '%v'", imageName, secrets)
}

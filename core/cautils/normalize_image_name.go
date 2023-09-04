package cautils

import (
	"github.com/docker/distribution/reference"
)

func NormalizeImageName(img string) (string, error) {
	name, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		return "", err
	}
	return name.String(), nil
}

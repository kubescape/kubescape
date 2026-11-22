package cautils

import (
	"strings"

	"github.com/distribution/reference"
)

func NormalizeImageName(img string) (string, error) {
	name, err := reference.ParseNormalizedNamed(strings.TrimSpace(img))
	if err != nil {
		return "", err
	}
	return name.String(), nil
}

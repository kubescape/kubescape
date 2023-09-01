package getter

import (
	"strings"
)

func contains(s []string, str string) bool {
	for _, v := range s {
		if strings.EqualFold(v, str) {
			return true
		}
	}

	return false
}

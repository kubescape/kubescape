package v2

import (
	"strings"
)

func maskID(id string) string {
	sep := "-"
	splitted := strings.Split(id, sep)
	if len(splitted) != 5 {
		return ""
	}
	str := splitted[0][:4]
	splitted[0] = splitted[0][4:]
	for i := range splitted {
		for j := 0; j < len(splitted[i]); j++ {
			str += "X"
		}
		str += sep
	}

	return strings.TrimSuffix(str, sep)
}

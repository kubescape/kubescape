package reporter

import (
	"net/url"
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

func parseHost(urlObj *url.URL) {
	if strings.Contains(urlObj.Host, "http://") {
		urlObj.Scheme = "http"
		urlObj.Host = strings.Replace(urlObj.Host, "http://", "", 1)
	} else {
		urlObj.Scheme = "https"
		urlObj.Host = strings.Replace(urlObj.Host, "https://", "", 1)
	}
}

package getter

import (
	"net/url"
	"path"
)

// buildAPIURL builds an URL pointing to the API backend.
func (api *KSCloudAPI) buildAPIURL(pth string, pairs ...string) string {
	return buildQuery(url.URL{
		Scheme: api.scheme,
		Host:   api.host,
		Path:   pth,
	}, pairs...)
}

// buildReportURL builds an URL pointing to the reporting endpoint.
func (api *KSCloudAPI) buildReportURL(pth string, pairs ...string) string {
	return buildQuery(url.URL{
		Scheme: api.reportscheme,
		Host:   api.reporthost,
		Path:   pth,
	}, pairs...)
}

// buildQuery builds an URL with query params.
//
// Params are provided in pairs (param name, value).
func buildQuery(u url.URL, pairs ...string) string {
	if len(pairs)%2 != 0 {
		panic("dev error: buildURL accepts query params in (name, value) pairs")
	}

	q := u.Query()

	for i := 0; i < len(pairs)-1; i += 2 {
		param := pairs[i]
		value := pairs[i+1]

		q.Add(param, value)
	}

	u.RawQuery = q.Encode()
	u.Path = path.Clean(u.Path)

	return u.String()
}

package getter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildURL(t *testing.T) {
	t.Parallel()

	ks := NewKSCloudAPICustomized(
		"api.example.com",                   // required
		WithReportURL("report.example.com"), // optional
	)

	t.Run("should build API URL with query params on https host", func(t *testing.T) {
		require.Equal(t,
			"https://api.example.com/path?q1=v1&q2=v2",
			ks.buildAPIURL("/path", "q1", "v1", "q2", "v2"),
		)
	})

	t.Run("should build API URL with query params on http host", func(t *testing.T) {
		ku := NewKSCloudAPICustomized("http://api.example.com")

		require.Equal(t,
			"http://api.example.com/path?q1=v1&q2=v2",
			ku.buildAPIURL("/path", "q1", "v1", "q2", "v2"),
		)
	})

	t.Run("should panic when params are not provided in pairs", func(t *testing.T) {
		require.Panics(t, func() {
			// notice how the linter detects wrong args
			_ = ks.buildAPIURL("/path", "q1", "v1", "q2") //nolint:staticcheck
		})
	})

	t.Run("should build report URL with query params on https host", func(t *testing.T) {
		require.Equal(t,
			"https://report.example.com/path?q1=v1&q2=v2",
			ks.buildReportURL("/path", "q1", "v1", "q2", "v2"),
		)
	})
}

func TestViewURL(t *testing.T) {
	t.Parallel()

	ks := NewKSCloudAPICustomized(
		"api.example.com",                   // required
		WithReportURL("report.example.com"), // optional
	)
	ks.SetAccountID("me")
}

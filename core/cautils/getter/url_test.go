package getter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildURL(t *testing.T) {
	t.Parallel()

	ks := NewKSCloudAPICustomized(
		"api.example.com", "auth.example.com", // required
		WithFrontendURL("ui.example.com"),   // optional
		WithReportURL("report.example.com"), // optional
	)

	t.Run("should build API URL with query params on https host", func(t *testing.T) {
		require.Equal(t,
			"https://api.example.com/path?q1=v1&q2=v2",
			ks.buildAPIURL("/path", "q1", "v1", "q2", "v2"),
		)
	})

	t.Run("should build API URL with query params on http host", func(t *testing.T) {
		ku := NewKSCloudAPICustomized("http://api.example.com", "auth.example.com")

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

	t.Run("should build UI URL with query params on https host", func(t *testing.T) {
		require.Equal(t,
			"https://ui.example.com/path?q1=v1&q2=v2",
			ks.buildUIURL("/path", "q1", "v1", "q2", "v2"),
		)
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
		"api.example.com", "auth.example.com", // required
		WithFrontendURL("ui.example.com"),   // optional
		WithReportURL("report.example.com"), // optional
	)
	ks.SetAccountID("me")
	ks.SetInvitationToken("invite")

	t.Run("should render UI report URL", func(t *testing.T) {
		require.Equal(t, "https://ui.example.com/repository-scanning/xyz", ks.ViewReportURL("xyz"))
	})

	t.Run("should render UI dashboard URL", func(t *testing.T) {
		require.Equal(t, "https://ui.example.com/dashboard", ks.ViewDashboardURL())
	})

	t.Run("should render UI RBAC URL", func(t *testing.T) {
		require.Equal(t, "https://ui.example.com/rbac-visualizer", ks.ViewRBACURL())
	})

	t.Run("should render UI scan URL", func(t *testing.T) {
		require.Equal(t, "https://ui.example.com/compliance/cluster", ks.ViewScanURL("cluster"))
	})

	t.Run("should render UI sign URL", func(t *testing.T) {
		require.Equal(t, "https://ui.example.com/account/sign-up?customerGUID=me&invitationToken=invite&utm_medium=createaccount&utm_source=ARMOgithub", ks.ViewSignURL())
	})
}

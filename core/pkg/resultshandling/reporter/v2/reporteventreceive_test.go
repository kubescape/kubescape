package v2

import (
	"testing"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestGetURL(t *testing.T) {
	// Test submit and registered url
	{
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:          "1234",
				Token:              "token",
				CustomerAdminEMail: "my@email",
				ClusterName:        "test",
			},
			"",
		)
		assert.Equal(t, "https://portal.armo.cloud/configuration-scanning/test?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
	}

	// Test submit and NOT registered url
	{

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				Token:       "token",
				ClusterName: "test",
			},
			"",
		)
		assert.Equal(t, "https://portal.armo.cloud/account/sign-up?customerGUID=1234&invitationToken=token&utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
	}
	// Test None submit url
	{
		reporter := NewReportMock(NO_SUBMIT_QUERY, "")
		assert.Equal(t, "https://portal.armo.cloud/account/sign-up?utm_source=GitHub&utm_medium=CLI&utm_campaign=no_submit", reporter.GetURL())
	}
	// Test None report url
	{
		reporter := NewReportMock("", "")
		assert.Equal(t, "https://portal.armo.cloud/account/sign-up", reporter.GetURL())
	}
}

package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// NativeFrameworks identifies all pre-built, native frameworks.
var NativeFrameworks = []string{"allcontrols", "nsa", "mitre"}

// var NativeFrameworks = []string{"clusterscan"}

type (
	// TenantResponse holds the credentials for a tenant.
	TenantResponse struct {
		TenantID  string `json:"tenantId"`
		Token     string `json:"token"`
		Expires   string `json:"expires"`
		AdminMail string `json:"adminMail,omitempty"`
	}

	// AttackTrack is an alias to the API type definition for attack tracks.
	AttackTrack = v1alpha1.AttackTrack

	// Framework is an alias to the API type definition for a framework.
	Framework = reporthandling.Framework

	// Control is an alias to the API type definition for a control.
	Control = reporthandling.Control

	// PostureExceptionPolicy is an alias to the API type definition for posture exception policy.
	PostureExceptionPolicy = armotypes.PostureExceptionPolicy

	// CustomerConfig is an alias to the API type definition for a customer configuration.
	CustomerConfig = armotypes.CustomerConfig

	// PostureReport is an alias to the API type definition for a posture report.
	PostureReport = reporthandlingv2.PostureReport
)

type (
	// internal data descriptors

	// feLoginData describes the input to a login challenge.
	feLoginData struct {
		Secret   string `json:"secret"`
		ClientId string `json:"clientId"`
	}

	// feLoginResponse describes the response to a login challenge.
	feLoginResponse struct {
		Token        string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		Expires      string `json:"expires"`
		ExpiresIn    int32  `json:"expiresIn"`
	}

	ksCloudSelectCustomer struct {
		SelectedCustomerGuid string `json:"selectedCustomer"`
	}
)

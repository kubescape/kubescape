package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// NativeFrameworks identifies all pre-built, native frameworks.
var NativeFrameworks = []string{"allcontrols", "nsa", "mitre"}

type (
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

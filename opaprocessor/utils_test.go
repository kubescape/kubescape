package opaprocessor

import (
	"testing"

	"github.com/armosec/kubescape/mocks"
	"github.com/stretchr/testify/assert"

	"github.com/armosec/opa-utils/reporthandling"
)

func TestConvertFrameworksToPolicies(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	policies := ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "")
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 3, len(policies.Controls))
}

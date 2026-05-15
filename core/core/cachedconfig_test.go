package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

func TestSetCachedConfig_AllFields(t *testing.T) {
	ks := &Kubescape{}
	setConfig := &metav1.SetConfig{
		Account:        "test-account",
		AccessKey:      "test-access-key",
		CloudAPIURL:    "https://api.test.com",
		CloudReportURL: "https://report.test.com",
	}
	err := ks.SetCachedConfig(setConfig)
	assert.NoError(t, err)
}

func TestSetCachedConfig_EmptyFields(t *testing.T) {
	ks := &Kubescape{}
	setConfig := &metav1.SetConfig{
		Account:        "",
		AccessKey:      "",
		CloudAPIURL:    "",
		CloudReportURL: "",
	}
	err := ks.SetCachedConfig(setConfig)
	assert.NoError(t, err)
}

func TestDeleteCachedConfig(t *testing.T) {
	ks := &Kubescape{}
	deleteConfig := &metav1.DeleteConfig{}
	err := ks.DeleteCachedConfig(deleteConfig)
	assert.NoError(t, err)
}

package cautils

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func mockConfigObj() *ConfigObj {
	return &ConfigObj{
		AccountID:      "aaa",
		ClusterName:    "ddd",
		CloudReportURL: "report.domain.com",
		CloudAPIURL:    "api.domain.com",
	}
}
func mockLocalConfig() *LocalConfig {
	return &LocalConfig{
		configObj: mockConfigObj(),
	}
}

func mockClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		configObj: mockConfigObj(),
	}
}
func TestConfig(t *testing.T) {
	co := mockConfigObj()
	cop := ConfigObj{}

	assert.NoError(t, json.Unmarshal(co.Config(), &cop))
	assert.Equal(t, co.AccountID, cop.AccountID)
	assert.Equal(t, co.CloudReportURL, cop.CloudReportURL)
	assert.Equal(t, co.CloudAPIURL, cop.CloudAPIURL)
	assert.Equal(t, "", cop.ClusterName) // Not copied to bytes

}

func TestITenantConfig(t *testing.T) {
	var lc ITenantConfig
	var c ITenantConfig
	lc = mockLocalConfig()
	c = mockClusterConfig()

	co := mockConfigObj()

	// test LocalConfig methods
	assert.Equal(t, co.AccountID, lc.GetAccountID())
	assert.Equal(t, co.ClusterName, lc.GetContextName())
	assert.Equal(t, co.CloudReportURL, lc.GetCloudReportURL())
	assert.Equal(t, co.CloudAPIURL, lc.GetCloudAPIURL())

	// test ClusterConfig methods
	assert.Equal(t, co.AccountID, c.GetAccountID())
	assert.Equal(t, co.ClusterName, c.GetContextName())
	assert.Equal(t, co.CloudReportURL, c.GetCloudReportURL())
	assert.Equal(t, co.CloudAPIURL, c.GetCloudAPIURL())
}

func TestUpdateConfigData(t *testing.T) {
	c := mockClusterConfig()

	configMap := &corev1.ConfigMap{}

	c.updateConfigData(configMap)

	assert.Equal(t, c.GetAccountID(), configMap.Data["accountID"])
	assert.Equal(t, c.GetCloudReportURL(), configMap.Data["cloudReportURL"])
	assert.Equal(t, c.GetCloudAPIURL(), configMap.Data["cloudAPIURL"])
}

func TestReadConfig(t *testing.T) {
	com := mockConfigObj()
	co := &ConfigObj{}

	b, e := json.Marshal(com)
	assert.NoError(t, e)

	readConfig(b, co)

	assert.Equal(t, com.AccountID, co.AccountID)
	assert.Equal(t, com.ClusterName, co.ClusterName)
	assert.Equal(t, com.CloudReportURL, co.CloudReportURL)
	assert.Equal(t, com.CloudAPIURL, co.CloudAPIURL)
}

func TestLoadConfigFromData(t *testing.T) {

	// use case: all data is in base config
	{
		c := mockClusterConfig()
		co := mockConfigObj()

		configMap := &corev1.ConfigMap{}

		c.updateConfigData(configMap)

		c.configObj = &ConfigObj{}

		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, c.GetAccountID(), co.AccountID)
		assert.Equal(t, c.GetContextName(), co.ClusterName)
		assert.Equal(t, c.GetCloudReportURL(), co.CloudReportURL)
		assert.Equal(t, c.GetCloudAPIURL(), co.CloudAPIURL)
	}

	// use case: all data is in config.json
	{
		c := mockClusterConfig()

		co := mockConfigObj()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		c.configObj = &ConfigObj{}

		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, c.GetAccountID(), co.AccountID)
		assert.Equal(t, c.GetCloudReportURL(), co.CloudReportURL)
		assert.Equal(t, c.GetCloudAPIURL(), co.CloudAPIURL)
	}

	// use case: some data is in config.json
	{
		c := mockClusterConfig()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		// add to map
		configMap.Data["cloudReportURL"] = c.configObj.CloudReportURL

		// delete the content
		c.configObj.CloudReportURL = ""

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.NotEmpty(t, c.GetAccountID())
		assert.NotEmpty(t, c.GetCloudReportURL())
	}

	// use case: some data is in config.json
	{
		c := mockClusterConfig()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		c.configObj.AccountID = "tttt"

		// add to map
		configMap.Data["accountID"] = mockConfigObj().AccountID

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, mockConfigObj().AccountID, c.GetAccountID())
	}

}

func TestAdoptClusterName(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		want        string
	}{
		{
			name:        "replace 1",
			clusterName: "my-name__is--ks",
			want:        "my-name__is-ks",
		},
		{
			name:        "replace 2",
			clusterName: "my-name1",
			want:        "my-name1",
		},
		{
			name:        "replace 3",
			clusterName: "my:name",
			want:        "my-name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdoptClusterName(tt.clusterName); got != tt.want {
				t.Errorf("AdoptClusterName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateCloudURLs(t *testing.T) {
	co := mockConfigObj()
	mockCloudAPIURL := "1-2-3-4.com"
	os.Setenv("KS_CLOUD_API_URL", mockCloudAPIURL)

	assert.NotEqual(t, co.CloudAPIURL, mockCloudAPIURL)
	updateCloudURLs(co)
	assert.Equal(t, co.CloudAPIURL, mockCloudAPIURL)
}

func Test_initializeCloudAPI(t *testing.T) {
	type args struct {
		c ITenantConfig
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test",
			args: args{
				c: mockClusterConfig(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializeCloudAPI(tt.args.c)
			cloud := getter.GetKSCloudAPIConnector()
			assert.Equal(t, "https://api.domain.com", cloud.GetCloudAPIURL())
			assert.Equal(t, "https://report.domain.com", cloud.GetCloudReportURL())
			assert.Equal(t, tt.args.c.GetAccountID(), cloud.GetAccountID())
		})
	}
}

func TestGetConfigMapNamespace(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{
			name: "no env",
			want: kubescapeNamespace,
		},
		{
			name: "default ns",
			env:  kubescapeNamespace,
			want: kubescapeNamespace,
		},
		{
			name: "custom ns",
			env:  "my-ns",
			want: "my-ns",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				_ = os.Setenv("KS_DEFAULT_CONFIGMAP_NAMESPACE", tt.env)
			}
			assert.Equalf(t, tt.want, GetConfigMapNamespace(), "GetConfigMapNamespace()")
		})
	}
}

const (
	anyString       string = "anyString"
	shouldNotUpdate string = "shouldNotUpdate"
	shouldUpdate    string = "shouldUpdate"
)

func checkIsUpdateCorrectly(t *testing.T, beforeField string, afterField string) {
	switch beforeField {
	case anyString:
		assert.Equal(t, anyString, afterField)
	case "":
		assert.Equal(t, shouldUpdate, afterField)
	}
}

func TestUpdateEmptyFields(t *testing.T) {

	tests := []struct {
		inCo  *ConfigObj
		outCo *ConfigObj
	}{
		{
			outCo: &ConfigObj{
				AccountID:      "",
				ClusterName:    "",
				CloudReportURL: "",
				CloudAPIURL:    "",
			},
			inCo: &ConfigObj{
				AccountID:      shouldUpdate,
				ClusterName:    shouldUpdate,
				CloudReportURL: shouldUpdate,
				CloudAPIURL:    shouldUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:      anyString,
				ClusterName:    "",
				CloudReportURL: "",
				CloudAPIURL:    "",
			},
			inCo: &ConfigObj{
				AccountID:      shouldNotUpdate,
				ClusterName:    shouldUpdate,
				CloudReportURL: shouldUpdate,
				CloudAPIURL:    shouldUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:      "",
				ClusterName:    anyString,
				CloudReportURL: anyString,
				CloudAPIURL:    anyString,
			},
			inCo: &ConfigObj{
				AccountID:      shouldUpdate,
				ClusterName:    shouldNotUpdate,
				CloudReportURL: shouldNotUpdate,
				CloudAPIURL:    shouldNotUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:      anyString,
				ClusterName:    anyString,
				CloudReportURL: "",
				CloudAPIURL:    anyString,
			},
			inCo: &ConfigObj{
				AccountID:      shouldNotUpdate,
				ClusterName:    shouldNotUpdate,
				CloudReportURL: shouldUpdate,
				CloudAPIURL:    shouldNotUpdate,
			},
		},
	}

	for i := range tests {
		beforeChangesOutCO := tests[i].outCo
		tests[i].outCo.updateEmptyFields(tests[i].inCo)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.AccountID, tests[i].outCo.AccountID)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudAPIURL, tests[i].outCo.CloudAPIURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudReportURL, tests[i].outCo.CloudReportURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.ClusterName, tests[i].outCo.ClusterName)
	}
}

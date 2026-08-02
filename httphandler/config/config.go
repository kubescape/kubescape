package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Namespace             string `mapstructure:"namespace"`
	ClusterName           string `mapstructure:"clusterName"`
	ContinuousPostureScan bool   `mapstructure:"continuousPostureScan"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	// A scoped instance instead of the viper package-level singleton: the
	// singleton accumulates state across calls (e.g. AddConfigPath appends
	// rather than replacing), so a second LoadConfig call in the same
	// process - a second cluster/namespace config, or just a test calling it
	// more than once - would read stale settings left over from a previous
	// call instead of a clean state.
	v := viper.New()
	v.AddConfigPath(path)
	v.SetConfigName("clusterData")
	v.SetConfigType("json")

	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = v.Unmarshal(&config)
	return config, err
}

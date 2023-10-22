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
	viper.AddConfigPath(path)
	viper.SetConfigName("clusterData")
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}

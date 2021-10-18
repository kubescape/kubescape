package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

var BuildNumber string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get current version",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Your current version is: " + BuildNumber)
		return nil
	},
}

func GetLatestVersion() (string, error) {
	latestVersion := "https://api.github.com/repos/armosec/kubescape/releases/latest"
	resp, err := http.Get(latestVersion)
	if err != nil {
		return "", fmt.Errorf("failed to get latest releases from '%s', reason: %s", latestVersion, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 301 < resp.StatusCode {
		return "", fmt.Errorf("failed to download file, status code: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from '%s', reason: %s", latestVersion, err.Error())
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", latestVersion, err.Error())
	}
	return fmt.Sprintf("%v", data["tag_name"]), nil
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

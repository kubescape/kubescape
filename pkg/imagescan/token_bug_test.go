package imagescan

import (
	"context"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestCloudAdaptors_IgnoreTokens_Bug(t *testing.T) {
	// Scenario 1: Username is correctly rejected
	credsUsername := RegistryCredentials{
		Username: "my-user",
		Password: "my-password",
	}

	azureAdaptor := NewAzureAdaptor()
	err := azureAdaptor.Login(context.Background(), "test.azurecr.io", credsUsername)
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")

	// Scenario 2: Token is SILENTLY IGNORED!
	credsToken := RegistryCredentials{
		Token: "my-secret-scoped-token",
	}

	err = azureAdaptor.Login(context.Background(), "test.azurecr.io", credsToken)
	
	// BUG FIXED: The adaptor now properly rejects the token!
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")

	// This behavior is identical for ECR and GCP adaptors:
	ecrAdaptor := NewAWSECRAdaptor()
	err = ecrAdaptor.Login(context.Background(), "12345.dkr.ecr.us-east-1.amazonaws.com", credsToken)
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")

	gcpAdaptor := NewGCPAdaptor()
	err = gcpAdaptor.Login(context.Background(), "us-docker.pkg.dev/my-project/my-repo", credsToken)
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")
}

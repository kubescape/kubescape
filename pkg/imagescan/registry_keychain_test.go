package imagescan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubResource struct {
	registry string
}

func (r stubResource) String() string      { return r.registry }
func (r stubResource) RegistryStr() string { return r.registry }

func TestNewRegistryKeychainImplementsAuthnKeychain(t *testing.T) {
	var _ = newRegistryKeychain()
}

// getProviderConfig no longer composes anything itself: composition (an
// existing docker login, then any cloud-provider keychains such as
// newACRKeychain in azure_adaptor.go) happens once, in newRegistryKeychain,
// at Service construction time. getProviderConfig just passes through
// whatever authn.Keychain it's given, per call.
func TestGetProviderConfigPassesKeychainThroughUnmodified(t *testing.T) {
	kc := newACRKeychain()
	config := getProviderConfig(RegistryCredentials{}, nil, ScanOptions{}, kc)

	assert.Same(t, kc, config.RegistryOptions.Keychain)
}

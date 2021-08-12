package secrethandling

import "testing"

func TestIsSecretTypeSupported(t *testing.T) {
	if !IsSecretTypeSupported("Opaque") {
		t.Errorf("secret is supported")
	}
}

func TestUpdateSubsecretPolicy(t *testing.T) {
	portalSubSecretDefinition := &PortalSubSecretDefinition{
		KeyID:         "8a14bc679340d3878a14bc679340d387",
		SubSecretName: "user",
	}
	subSecName := "user"
	subSecKeyID := "8a14bc679340d3878a14bc679340d381"
	if updated := updateSubsecretPolicy(portalSubSecretDefinition, subSecName, subSecKeyID); !updated {
		t.Errorf("should update")
	}
	if portalSubSecretDefinition.KeyID != subSecKeyID {
		t.Errorf("keyID not updated")
	}

}
func TestValidateSecretIDK8s(t *testing.T) {
	if err := ValidateSecretID(""); err == nil {
		t.Errorf("A expected to fail")
	}
	if err := ValidateSecretID("sid://"); err == nil {
		t.Errorf("B expected to fail")
	}
	if err := ValidateSecretID("sid://cluster-"); err == nil {
		t.Errorf("C expected to fail")
	}
	if err := ValidateSecretID("sid://cluster-bla"); err != nil {
		t.Errorf("D expected to pass")
	}
	if err := ValidateSecretID("sid://cluster-bla"); err != nil {
		t.Errorf("E expected to pass")
	}
	if err := ValidateSecretID("sid://cluster-bla/"); err != nil {
		t.Errorf("F expected to pass")
	}
	if err := ValidateSecretID("sid://cluster-bla/namespace-"); err == nil {
		t.Errorf("G expected to fail")
	}
	if err := ValidateSecretID("sid://cluster-bla/namespace-bla/secret-bla"); err != nil {
		t.Errorf("H expected to pass")
	}
	if err := ValidateSecretID("sid://cluster-bla/namespace-bla/secret-bla/subsecret-bla"); err != nil {
		t.Errorf("I expected to pass")
	}

}

func TestValidateSecretIDNative(t *testing.T) {
	if err := ValidateSecretID(""); err == nil {
		t.Errorf("A expected to fail")
	}
	if err := ValidateSecretID("sid://"); err == nil {
		t.Errorf("B expected to fail")
	}
	if err := ValidateSecretID("sid://datacenter-"); err == nil {
		t.Errorf("C expected to fail")
	}
	if err := ValidateSecretID("sid://datacenter-bla"); err != nil {
		t.Errorf("D expected to pass")
	}
	if err := ValidateSecretID("sid://datacenter-bla"); err != nil {
		t.Errorf("E expected to pass")
	}
	if err := ValidateSecretID("sid://datacenter-bla/"); err != nil {
		t.Errorf("F expected to pass")
	}
	if err := ValidateSecretID("sid://datacenter-bla/project-"); err == nil {
		t.Errorf("G expected to fail")
	}
	if err := ValidateSecretID("sid://datacenter-pod_seal-njca/project-default/secret-temp"); err != nil {
		t.Errorf("H expected to pass")
	}
	if err := ValidateSecretID("sid://datacenter-bla/project-bla/secret-bla/subsecret-bla"); err != nil {
		t.Errorf("I expected to pass")
	}

}

func TestIsSIDK8s(t *testing.T) {
	if IsSIDK8s("sid://datacenter-bla/project-bla/secret-bla") {
		t.Errorf("expect to be native")
	}
	if !IsSIDK8s("sid://") {
		t.Errorf("A expect to be k8s")
	}
	if !IsSIDK8s("sid://cluster-bla") {
		t.Errorf("B expect to be k8s")
	}
	if !IsSIDK8s("sid://cluster-bla/namespace-bla/secret-bla") {
		t.Errorf("C expect to be k8s")
	}

}

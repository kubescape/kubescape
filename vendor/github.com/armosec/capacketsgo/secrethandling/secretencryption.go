package secrethandling

import "fmt"

// GetFieldsToEncrypt get fields from secret data to encrypt
func GetFieldsToEncrypt(secretDate map[string][]byte, secretPolicy *SecretAccessPolicy, subsecretName string) (map[string]string, error) {
	fieldsToEncrypt, err := GetFieldsToEncryptFromSecretPolicy(secretDate, secretPolicy)
	if err != nil || len(fieldsToEncrypt) != 0 { // if subsecrets are defined in secret policy
		return fieldsToEncrypt, err
	}

	// if secret policy doesn't have subsecrets
	if subsecretName != "" {
		secretData, ok := secretDate[subsecretName]
		if !ok {
			return fieldsToEncrypt, fmt.Errorf("subsecret %s not found in secret data", subsecretName)
		}
		if !HasSecretTLV(secretData) {
			fieldsToEncrypt[subsecretName] = ""
		}
	} else {
		for subsecret, secretData := range secretDate {
			if !HasSecretTLV(secretData) {
				fieldsToEncrypt[subsecret] = ""
			}
		}

	}
	return fieldsToEncrypt, nil
}

// GetFieldsToEncryptFromSecretPolicy -
func GetFieldsToEncryptFromSecretPolicy(secretDate map[string][]byte, secretPolicy *SecretAccessPolicy) (map[string]string, error) {
	fieldsToEncrypt := make(map[string]string)
	if secretPolicy == nil || secretPolicy.Secrets == nil {
		return fieldsToEncrypt, nil
	}
	for secrets := range secretPolicy.Secrets {
		for _, subsecret := range secretPolicy.Secrets[secrets].KeyIDs {
			subsecretData, err := SubsecretToEncrypt(secretDate, subsecret.SubSecretName)
			if err != nil {
				return fieldsToEncrypt, err
			}
			if !HasSecretTLV(subsecretData) {
				fieldsToEncrypt[subsecret.SubSecretName] = subsecret.KeyID
			}
		}
	}
	return fieldsToEncrypt, nil
}

// SubsecretToEncrypt check if the given subsecret should be encrypted
func SubsecretToEncrypt(subsecrets map[string][]byte, subsecretName string) ([]byte, error) {
	secretData, ok := subsecrets[subsecretName]
	if !ok {
		return []byte{}, fmt.Errorf("subsecret %s not found in data", subsecretName)
	}
	if _, ok := subsecrets[subsecretName+ArmoShadowSubsecretSuffix]; ok {
		return []byte{}, nil
	}
	return secretData, nil
}

// GetFieldsToDecrypt get encrypted secret fields
func GetFieldsToDecrypt(secretDate map[string][]byte, subsecretName string) ([]string, error) {
	fieldsToDecrypt := []string{}
	if subsecretName != "" {
		secretData, ok := secretDate[subsecretName]
		if !ok {
			return fieldsToDecrypt, fmt.Errorf("subsecret %s not found in secret data", subsecretName)
		}
		if HasSecretTLV(secretData) {
			fieldsToDecrypt = append(fieldsToDecrypt, subsecretName)
		}
	} else {
		for subsecret, secretData := range secretDate {
			if HasSecretTLV(secretData) {
				fieldsToDecrypt = append(fieldsToDecrypt, subsecret)
			}
		}

	}
	return fieldsToDecrypt, nil
}

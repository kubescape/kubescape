package cautils

import "testing"

func TestValidateAccountID(t *testing.T) {
	type fields struct {
		Account string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid account ID",
			fields: fields{
				Account: "22019933-feac-4012-a8eb-e81461ba6655",
			},
			wantErr: false,
		},
		{
			name: "invalid account ID",
			fields: fields{
				Account: "22019933-feac-4012-a8eb-e81461ba665",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAccountID(tt.fields.Account); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAccountID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

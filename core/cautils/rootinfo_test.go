package cautils

import "testing"

func TestCredentials_Validate(t *testing.T) {
	type fields struct {
		Account   string
		ClientID  string
		SecretKey string
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
		{
			name: "valid client ID",
			fields: fields{
				ClientID: "22019933-feac-4012-a8eb-e81461ba6655",
			},
			wantErr: false,
		},
		{
			name: "invalid client ID",
			fields: fields{
				ClientID: "22019933-feac-4012-a8eb-e81461ba665",
			},
			wantErr: true,
		},
		{
			name: "valid secret key",
			fields: fields{
				SecretKey: "22019933-feac-4012-a8eb-e81461ba6655",
			},
			wantErr: false,
		},
		{
			name: "invalid secret key",
			fields: fields{
				SecretKey: "22019933-feac-4012-a8eb-e81461ba665",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := &Credentials{
				Account:   tt.fields.Account,
				ClientID:  tt.fields.ClientID,
				SecretKey: tt.fields.SecretKey,
			}
			if err := credentials.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Credentials.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

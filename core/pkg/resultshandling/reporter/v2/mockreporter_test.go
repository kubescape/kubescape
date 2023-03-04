package reporter

import (
	"testing"
)

func TestReportMock_GetURL(t *testing.T) {
	type fields struct {
		query   string
		message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestReportMock_GetURL",
			fields: fields{
				query:   "https://kubescape.io",
				message: "some message",
			},
			want: "https://kubescape.io",
		},
		{
			name: "TestReportMock_GetURL_empty",
			fields: fields{
				query:   "",
				message: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportMock := &ReportMock{
				query:   tt.fields.query,
				message: tt.fields.message,
			}
			if got := reportMock.GetURL(); got != tt.want {
				t.Errorf("ReportMock.GetURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportMock_strToDisplay(t *testing.T) {
	type fields struct {
		query   string
		message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestReportMock_strToDisplay",
			fields: fields{
				query:   "https://kubescape.io",
				message: "some message",
			},
			want: "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nScan results have not been submitted: some message\nFor more details: https://kubescape.io\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n",
		},
		{
			name: "TestReportMock_strToDisplay_empty",
			fields: fields{
				query:   "https://kubescape.io",
				message: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportMock := &ReportMock{
				query:   tt.fields.query,
				message: tt.fields.message,
			}
			if got := reportMock.strToDisplay(); got != tt.want {
				t.Errorf("ReportMock.strToDisplay() = %v, want %v", got, tt.want)
			}
		})
	}
}

package reporter

import "testing"

func TestReportMock_GetURL(t *testing.T) {
	type fields struct {
		query string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "TestReportMock_GetURL",
			fields: struct {
				query string
			}{
				query: "https://kubescape.io",
			},
			want: "https://kubescape.io?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub",
		},
		{
			name: "TestReportMock_GetURL_empty",
			fields: struct {
				query string
			}{
				query: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportMock := &ReportMock{
				query: tt.fields.query,
			}
			if got := reportMock.GetURL(); got != tt.want {
				t.Errorf("ReportMock.GetURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

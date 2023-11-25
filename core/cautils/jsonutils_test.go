package cautils

import (
	"reflect"
	"testing"
)

func TestPrettyJson(t *testing.T) {
	type args struct {
		data interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "SimpleJson",
			args: args{
				data: map[string]interface{}{
					"key": "value",
				},
			},
			want: []byte(`{
  "key": "value"
}
`),
			wantErr: false,
		},
		{
			name: "NestedJson",
			args: args{
				data: map[string]interface{}{
					"key": map[string]interface{}{
						"key": "value",
					},
				},
			},
			want: []byte(`{
  "key": {
    "key": "value"
  }
}
`),
			wantErr: false,
		},
		{
			name: "ComplexJson",
			args: args{
				data: map[string]interface{}{
					"A": "B",
					"C": map[string]interface{}{
						"D": "E",
						"F": map[string]interface{}{
							"G": "H",
							"I": "J",
						},
					},
				},
			},
			want: []byte(`{
  "A": "B",
  "C": {
    "D": "E",
    "F": {
      "G": "H",
      "I": "J"
    }
  }
}
`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrettyJson(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrettyJson() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PrettyJson() = %v, want %v", got, tt.want)
			}
		})
	}
}

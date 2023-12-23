package cautils

import (
	"reflect"
	"sort"
	"testing"
)

func TestMapExternalResource(t *testing.T) {
	type args struct {
		externalResourceMap ExternalResources
		resources           []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "One resource",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
				},
				resources: []string{"ImageVulnerabilities"},
			},
			want: []string{"ImageVulnerabilities"},
		},
		{
			name: "Two resources",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
					"KubeletConfiguration": {"KubeletConfiguration"},
				},
				resources: []string{"ImageVulnerabilities", "KubeletConfiguration"},
			},
			want: []string{"ImageVulnerabilities", "KubeletConfiguration"},
		},
		{
			name: "No resources",
			args: args{
				externalResourceMap: make(ExternalResources),
				resources:           []string{},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapExternalResource(tt.args.externalResourceMap, tt.args.resources)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapExternalResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapHostResources(t *testing.T) {
	type args struct {
		externalResourceMap ExternalResources
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Host Sensor Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"KernelVersion": {"KubeletConfiguration"},
				},
			},
			want: []string{"KernelVersion"},
		},
		{
			name: "Not Host Sensor Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
				},
			},
			want: nil,
		},
		{
			name: "Mixed resources",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
					"KernelVersion":        {"KubeletConfiguration"},
				},
			},
			want: []string{"KernelVersion"},
		},
		{
			name: "No resources",
			args: args{
				externalResourceMap: make(ExternalResources),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapHostResources(tt.args.externalResourceMap)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapHostResources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapImageVulnResources(t *testing.T) {
	type args struct {
		externalResourceMap ExternalResources
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Image Vulnerability Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
				},
			},
			want: []string{"ImageVulnerabilities"},
		},
		{
			name: "Not Image Vulnerability Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"KernelVersion": {"KubeletConfiguration"},
				},
			},
			want: nil,
		},
		{
			name: "Mixed resources",
			args: args{
				externalResourceMap: ExternalResources{
					"ImageVulnerabilities": {"ImageVulnerabilities"},
					"KernelVersion":        {"KubeletConfiguration"},
				},
			},
			want: []string{"ImageVulnerabilities"},
		},
		{
			name: "No resources",
			args: args{
				externalResourceMap: make(ExternalResources),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapImageVulnResources(tt.args.externalResourceMap)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapImageVulnResources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapCloudResources(t *testing.T) {
	type args struct {
		externalResourceMap ExternalResources
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Cloud Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"ClusterDescribe": {"CloudProviderInfo"},
				},
			},
			want: []string{"ClusterDescribe"},
		},
		{
			name: "Not Cloud Resource",
			args: args{
				externalResourceMap: ExternalResources{
					"KernelVersion": {"KubeletConfiguration"},
				},
			},
			want: nil,
		},
		{
			name: "Mixed resources",
			args: args{
				externalResourceMap: ExternalResources{
					"ClusterDescribe": {"CloudProviderInfo"},
					"KernelVersion":   {"KubeletConfiguration"},
				},
			},
			want: []string{"ClusterDescribe"},
		},
		{
			name: "No resources",
			args: args{
				externalResourceMap: make(ExternalResources),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapCloudResources(tt.args.externalResourceMap)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapCloudResources() = %v, want %v", got, tt.want)
			}
		})
	}
}

package mcpserver

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultSBOMPackageListLimit = 100
	maxSBOMPackageListLimit     = 500
)

// sbomEntry describes one stored SBOM without its content.
type sbomEntry struct {
	Namespace string `json:"namespace"`
	SBOMName  string `json:"sbom_name"`
	ImageID   string `json:"image_id,omitempty"`
	ImageTag  string `json:"image_tag,omitempty"`
	Status    string `json:"status,omitempty"`
}

type sbomListResponse struct {
	SBOMs    []sbomEntry `json:"sboms"`
	Continue string      `json:"continue,omitempty"`
}

func listSBOMEntries(items []v1beta1.SBOMSyft) []sbomEntry {
	entries := make([]sbomEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, sbomEntry{
			Namespace: item.Namespace,
			SBOMName:  item.Name,
			ImageID:   item.Annotations[helpersv1.ImageIDMetadataKey],
			ImageTag:  item.Annotations[helpersv1.ImageTagMetadataKey],
			Status:    item.Annotations[helpersv1.StatusMetadataKey],
		})
	}
	return entries
}

// sbomPackageEntry is one package of an SBOM. Locations, CPEs and the
// cataloger metadata are left out: they make up most of the document and an
// agent rarely needs them to answer "is this package in the image".
type sbomPackageEntry struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	Language string   `json:"language,omitempty"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses"`
}

type sbomPackageListResponse struct {
	SBOMName string `json:"sbom_name"`
	// Status is the SBOM's kubescape.io/status annotation. An SBOM that was
	// too large to store has a status and no packages, which is not the same
	// as an image with no packages.
	Status     string             `json:"status,omitempty"`
	Distro     string             `json:"distro,omitempty"`
	Total      int                `json:"total"`
	Returned   int                `json:"returned"`
	Truncated  bool               `json:"truncated"`
	NextOffset *int               `json:"next_offset,omitempty"`
	Packages   []sbomPackageEntry `json:"packages"`
}

type sbomPackageListOptions struct {
	name        string // case-insensitive substring; empty means no filter
	packageType string // exact, case-insensitive; empty means no filter
	limit       int
	offset      int
}

// parseSBOMPackageListOptions reads the optional filter and paging arguments
// of list_sbom_packages.
func parseSBOMPackageListOptions(arguments map[string]any) (sbomPackageListOptions, *mcp.CallToolResult) {
	opts := sbomPackageListOptions{limit: defaultSBOMPackageListLimit}

	name, toolErr := mcpStringArg(arguments, "name")
	if toolErr != nil {
		return opts, toolErr
	}
	opts.name = strings.ToLower(strings.TrimSpace(name))

	packageType, toolErr := mcpStringArg(arguments, "package_type")
	if toolErr != nil {
		return opts, toolErr
	}
	opts.packageType = strings.TrimSpace(packageType)

	limit, set, toolErr := mcpIntArg(arguments, "limit")
	if toolErr != nil {
		return opts, toolErr
	}
	if set {
		if limit < 1 || limit > maxSBOMPackageListLimit {
			return opts, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("limit must be between 1 and %d", maxSBOMPackageListLimit),
				map[string]any{"argument": "limit"})
		}
		opts.limit = limit
	}

	offset, _, toolErr := mcpIntArg(arguments, "offset")
	if toolErr != nil {
		return opts, toolErr
	}
	if offset < 0 {
		return opts, mcpToolError(ErrCodeInvalidArgument, "offset must not be negative", map[string]any{"argument": "offset"})
	}
	opts.offset = offset
	return opts, nil
}

// listSBOMPackages filters the SBOM's packages and orders them by name,
// version, type and purl, so that paging with offset is stable. The same
// package found in several places is listed once, with the licenses of all
// its copies. A package is identified by its purl, or by name, version and
// type when it has none, so two Java packages with the same name and version
// but different group IDs are both listed. Copies are grouped before the
// filters run, and a package is listed when any of its copies matches, so a
// filter never drops licenses that only another copy carries. The name and
// type shown are those of the first matching copy.
func listSBOMPackages(sbom *v1beta1.SBOMSyft, opts sbomPackageListOptions) sbomPackageListResponse {
	doc := sbom.Spec.Syft
	seen := map[[4]string]int{}
	all := []sbomPackageEntry{}
	matched := []bool{}
	for _, p := range doc.Artifacts {
		key := [4]string{p.PURL}
		if p.PURL == "" {
			key = [4]string{"", p.Name, p.Version, p.Type}
		}
		i, ok := seen[key]
		if !ok {
			i = len(all)
			seen[key] = i
			matched = append(matched, false)
			all = append(all, sbomPackageEntry{
				Name:     p.Name,
				Version:  p.Version,
				Type:     p.Type,
				Language: p.Language,
				PURL:     p.PURL,
				Licenses: []string{},
			})
		}
		if (opts.name == "" || strings.Contains(strings.ToLower(p.Name), opts.name)) &&
			(opts.packageType == "" || strings.EqualFold(p.Type, opts.packageType)) && !matched[i] {
			matched[i] = true
			all[i].Name, all[i].Version, all[i].Type, all[i].Language = p.Name, p.Version, p.Type, p.Language
		}
		for _, l := range p.Licenses {
			value := l.SPDXExpression
			if value == "" {
				value = l.Value
			}
			if value != "" && !slices.Contains(all[i].Licenses, value) {
				all[i].Licenses = append(all[i].Licenses, value)
			}
		}
	}
	entries := []sbomPackageEntry{}
	for i, e := range all {
		if matched[i] {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.PURL < b.PURL
	})

	resp := sbomPackageListResponse{
		SBOMName: sbom.Name,
		Status:   sbom.Annotations[helpersv1.StatusMetadataKey],
		Distro:   strings.TrimSpace(doc.Distro.ID + " " + doc.Distro.VersionID),
		Total:    len(entries),
		Packages: []sbomPackageEntry{},
	}
	if opts.offset < len(entries) {
		end := min(opts.offset+opts.limit, len(entries))
		resp.Packages = entries[opts.offset:end]
		if end < len(entries) {
			resp.Truncated = true
			next := end
			resp.NextOffset = &next
		}
	}
	resp.Returned = len(resp.Packages)
	return resp
}

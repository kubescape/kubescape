package cautils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/zclconf/go-cty/cty"
)

const (
	// maxTerraformFileBytes is the default fallback limit matching DefaultMaxFileSize.
	maxTerraformFileBytes = DefaultMaxFileSize
)

var (
	// ErrTerraformFileNotRegular is returned when a Terraform file is not a regular file.
	ErrTerraformFileNotRegular = errors.New("terraform file is not a regular file")
	// ErrTerraformFileTooLarge is returned when a Terraform file exceeds the maximum allowed size.
	ErrTerraformFileTooLarge = errors.New("terraform file exceeds maximum size limit")
)

// openTerraformFile opens path for reading and rejects anything but a regular file.
// A pre-open stat check prevents opening device nodes (e.g. tape or character devices).
// O_NONBLOCK keeps opening a FIFO from waiting for a writer, and descriptor-based
// validation ensures a path swapped after stat cannot slip past.
func openTerraformFile(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	cleaned := filepath.Clean(path)
	statInfo, err := os.Stat(cleaned)
	if err != nil {
		return nil, err
	}
	if statInfo.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrTerraformFileNotRegular)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrTerraformFileNotRegular, path)
	}

	file, err := os.OpenFile(cleaned, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrTerraformFileNotRegular)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: %q", ErrTerraformFileNotRegular, path)
	}
	return file, nil
}

// readTerraformFile returns the contents of the Terraform file at path, reading at most
// getMaxFileSize() bytes (configurable via KUBESCAPE_MAX_FILE_SIZE, defaulting to
// DefaultMaxFileSize) so that reading remains bounded.
func readTerraformFile(path string) ([]byte, error) {
	file, err := openTerraformFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limit := getMaxFileSize()

	info, err := file.Stat()
	if err == nil && info.Size() > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrTerraformFileTooLarge, path, limit)
	}

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrTerraformFileTooLarge, path, limit)
	}
	return data, nil
}

func isTerraformDirectory(path string) bool {
	if !isDir(path) {
		return false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".tf" {
			return true
		}
	}
	return false
}

func IsTerraformFile(path string) bool {
	return filepath.Ext(path) == ".tf"
}

type TerraformDirectory struct {
	path         string
	workspaceDir string
}

func NewTerraformDirectory(path string, workspaceOpt ...string) *TerraformDirectory {
	td := &TerraformDirectory{path: path}
	if len(workspaceOpt) > 0 {
		td.workspaceDir = workspaceOpt[0]
	}
	return td
}

// GetWorkloads extracts embedded K8s manifests from resource "kubernetes_manifest" blocks.
// Only literal values and var.x references with a same-module default are resolved —
// deliberately not a full Terraform evaluator (see LoadResourcesFromTerraform doc).
func (td *TerraformDirectory) GetWorkloads(path string) (map[string][]workloadinterface.IMetadata, []error) {
	parser := hclparse.NewParser()
	var errs []error

	tfFiles, err := filepath.Glob(filepath.Join(path, "*.tf"))
	if err != nil {
		return nil, []error{err}
	}

	varDefaults := map[string]cty.Value{}
	var files []*hcl.File
	var parsedPaths []string
	for _, f := range tfFiles {
		if td.workspaceDir != "" && !pathcontainment.IsPathContained(td.workspaceDir, f) {
			logger.L().Warning("Skipping Terraform file outside workspace root", helpers.String("path", f), helpers.String("workspace", td.workspaceDir))
			continue
		}
		content, readErr := readTerraformFile(f)
		if readErr != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", f, readErr))
			continue
		}
		file, diags := parser.ParseHCL(content, f)
		if diags.HasErrors() {
			errs = append(errs, fmt.Errorf("parsing %s: %w", f, diags))
			continue
		}
		files = append(files, file)
		parsedPaths = append(parsedPaths, f)
		collectVariableDefaults(file.Body, varDefaults)
	}

	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"var": cty.ObjectVal(varDefaults)},
	}

	workloads := map[string][]workloadinterface.IMetadata{}
	for i, file := range files {
		manifests, fileErrs := extractKubernetesManifests(file.Body, evalCtx)
		errs = append(errs, fileErrs...)

		typedManifests, typedErrs := extractTypedResources(file.Body, evalCtx)
		errs = append(errs, typedErrs...)
		manifests = append(manifests, typedManifests...)

		src := parsedPaths[i]
		for j, m := range manifests {
			data, err := json.Marshal(m)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: manifest %d: %w", src, j, err))
				continue
			}
			wls, err := ReadFile(data, JSON_FILE_FORMAT)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: manifest %d not a valid k8s object: %w", src, j, err))
				continue
			}
			for _, w := range wls {
				if td.workspaceDir != "" && !pathcontainment.IsPathContained(td.workspaceDir, src) {
					continue
				}
				lw := localworkload.NewLocalWorkload(w.GetObject())
				lw.SetPath(fmt.Sprintf("%s:%d", src, j))
				workloads[src] = append(workloads[src], lw)
			}
		}
	}
	return workloads, errs
}

// collectVariableDefaults walks top-level `variable "x" { default = ... }` blocks
// and records the default so resource blocks can resolve var.x references.
// Variables with no default are intentionally skipped — they stay unresolved.
func collectVariableDefaults(body hcl.Body, defaults map[string]cty.Value) {
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "variable", LabelNames: []string{"name"}},
		},
	}
	content, _, _ := body.PartialContent(schema)
	for _, block := range content.Blocks {
		if len(block.Labels) == 0 {
			continue
		}
		name := block.Labels[0]
		attrSchema := &hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{{Name: "default"}},
		}
		attrContent, _, _ := block.Body.PartialContent(attrSchema)
		attr, ok := attrContent.Attributes["default"]
		if !ok {
			continue
		}
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}
		defaults[name] = val
	}
}

// extractKubernetesManifests finds resource "kubernetes_manifest" "x" { manifest = {...} }
// blocks and returns each manifest as a plain Go map, ready for json.Marshal.
func extractKubernetesManifests(body hcl.Body, evalCtx *hcl.EvalContext) ([]map[string]interface{}, []error) {
	var errs []error
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
		},
	}
	content, _, _ := body.PartialContent(schema)

	var manifests []map[string]interface{}
	for _, block := range content.Blocks {
		if len(block.Labels) < 2 || block.Labels[0] != "kubernetes_manifest" {
			continue
		}
		attrSchema := &hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{{Name: "manifest"}},
		}
		attrContent, _, _ := block.Body.PartialContent(attrSchema)
		attr, ok := attrContent.Attributes["manifest"]
		if !ok {
			continue
		}
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			logger.L().Warning("skipping unresolved kubernetes_manifest reference",
				helpers.String("resource", block.Labels[1]), helpers.Error(diags))
			continue
		}
		goVal := ctyToGo(val)
		m, ok := goVal.(map[string]interface{})
		if !ok {
			errs = append(errs, fmt.Errorf("resource %q: manifest is not an object", block.Labels[1]))
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, errs
}

// ctyToGo converts a cty.Value into plain Go types (map[string]interface{}, []interface{},
// string, float64, bool, nil) so it can be json.Marshal'd. Unresolved/unknown values
// (e.g. references to things we didn't evaluate) become nil rather than erroring, so one
// unresolved field doesn't drop the whole manifest.
func ctyToGo(v cty.Value) interface{} {
	if v.IsNull() || !v.IsKnown() {
		return nil
	}
	t := v.Type()
	switch {
	case t.IsObjectType() || t.IsMapType():
		out := map[string]interface{}{}
		for k, val := range v.AsValueMap() {
			out[k] = ctyToGo(val)
		}
		return out
	case t.IsTupleType() || t.IsListType() || t.IsSetType():
		var out []interface{}
		for _, val := range v.AsValueSlice() {
			out = append(out, ctyToGo(val))
		}
		return out
	case t == cty.String:
		return v.AsString()
	case t == cty.Bool:
		return v.True()
	case t == cty.Number:
		return json.Number(v.AsBigFloat().Text('f', -1))
	default:
		return nil
	}
}

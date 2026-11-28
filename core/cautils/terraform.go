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
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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
	// sourceLocations holds the resource block location of each workload of
	// the last GetWorkloads call, by workload path.
	sourceLocations map[string]SourceLocation
}

func NewTerraformDirectory(path string, workspaceOpt ...string) *TerraformDirectory {
	td := &TerraformDirectory{path: path}
	if len(workspaceOpt) > 0 {
		td.workspaceDir = workspaceOpt[0]
	}
	return td
}

// GetWorkloads extracts embedded K8s manifests from resource "kubernetes_manifest" blocks.
// Literals, built-in functions, locals, and var.x references resolved from a
// same-module default or an auto-loaded tfvars file are evaluated — deliberately
// not a full Terraform evaluator (see LoadResourcesFromTerraform doc).
func (td *TerraformDirectory) GetWorkloads(path string) (map[string][]workloadinterface.IMetadata, []error) {
	td.sourceLocations = nil
	path = filepath.Clean(path)
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, []error{err}
	}

	parser := hclparse.NewParser()
	var errs []error
	// Override files (override.tf, *_override.tf) are merged into the primary
	// files rather than read as configuration of their own, as in Terraform.
	// os.ReadDir lists entries sorted by name, the order Terraform applies
	// override files in.
	var files, overrideFiles []*hcl.File
	var parsedPaths []string
	for _, entry := range entries {
		if !IsTerraformFile(entry.Name()) {
			continue
		}
		f := filepath.Join(path, entry.Name())
		if td.workspaceDir != "" && !pathcontainment.IsPathContained(td.workspaceDir, f) {
			logger.L().Warning("Skipping Terraform file outside workspace root", helpers.String("path", f), helpers.String("workspace", td.workspaceDir))
			continue
		}
		// Let the reader report invalid .tf entries, including directories.
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
		if isTerraformOverrideFile(f) {
			overrideFiles = append(overrideFiles, file)
			continue
		}
		files = append(files, file)
		parsedPaths = append(parsedPaths, f)
	}

	merged, overrideErrs := applyTerraformOverrides(files, overrideFiles)
	errs = append(errs, overrideErrs...)
	files = merged.files

	varDefaults := map[string]cty.Value{}
	declared := map[string]terraformVariable{}
	for _, file := range files {
		collectVariableDefaults(file.Body, varDefaults, declared)
	}
	applyTerraformVariableOverrides(merged.variables, varDefaults, declared)
	if len(files) > 0 {
		errs = append(errs, applyTerraformVarFiles(parser, path, td.workspaceDir, declared, varDefaults)...)
	}
	locals, localExpressions := resolveLocals(files, varDefaults)
	evalCtx := newTerraformEvalContext(varDefaults, locals)
	references := terraformReferenceChecker{localExpressions: localExpressions, moduleCtx: evalCtx, declaredVariables: declared, sourceSizes: merged.sourceSizes}

	workloads := map[string][]workloadinterface.IMetadata{}
	for i, file := range files {
		manifests, fileErrs := extractKubernetesManifestResources(file.Body, evalCtx, references)
		errs = append(errs, fileErrs...)

		typedManifests, typedErrs := extractTypedResourceManifests(file.Body, evalCtx, references)
		errs = append(errs, typedErrs...)
		for _, manifest := range typedManifests {
			// A resource with unresolved values is reported through its
			// *terraformResourceError instead of being scanned incomplete.
			if !manifest.incomplete {
				manifests = append(manifests, manifest)
			}
		}

		src := parsedPaths[i]
		for j, manifest := range manifests {
			workloadPath := terraformWorkloadPath(src, j)
			td.recordSourceLocation(workloadPath, manifest.source)
			data, err := json.Marshal(manifest.object)
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
				lw.SetPath(workloadPath)
				workloads[src] = append(workloads[src], lw)
			}
		}
	}
	return workloads, errs
}

// collectVariableDefaults walks top-level `variable "x" { default = ... }` blocks
// and records the default so resource blocks can resolve var.x references.
// Every declared variable is recorded with its type constraint so tfvars values
// are only accepted for declared variables and converted the way Terraform does.
func collectVariableDefaults(body hcl.Body, defaults map[string]cty.Value, declared map[string]terraformVariable) {
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
			Attributes: []hcl.AttributeSchema{{Name: "default"}, {Name: "type"}, {Name: "nullable"}},
		}
		attrContent, _, _ := block.Body.PartialContent(attrSchema)
		variable := newTerraformVariable(attrContent.Attributes["type"])
		if attr, ok := attrContent.Attributes["nullable"]; ok {
			if nonNullable, ok := terraformVariableNonNullable(attr); ok {
				variable.nonNullable = nonNullable
			}
		}
		if attr, ok := attrContent.Attributes["default"]; ok {
			if val, diags := attr.Expr.Value(nil); !diags.HasErrors() {
				if val, err := variable.convert(val); err == nil {
					defaults[name] = val
					variable.defaultVal = val
				}
			}
		}
		declared[name] = variable
	}
}

// terraformVariableNonNullable reads a variable's nullable argument, reporting
// whether it is set to false. As in Terraform, a value that converts to bool,
// such as "false", is accepted; ok is false when the value isn't a known bool
// after conversion.
func terraformVariableNonNullable(attr *hcl.Attribute) (nonNullable, ok bool) {
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || !val.IsWhollyKnown() || val.IsNull() {
		return false, false
	}
	val, err := convert.Convert(val, cty.Bool)
	if err != nil || !val.IsKnown() || val.IsNull() {
		return false, false
	}
	return val.False(), true
}

// extractKubernetesManifests finds resource "kubernetes_manifest" "x" { manifest = {...} }
// blocks and returns each manifest as a plain Go map, ready for json.Marshal.
// A resource with count or for_each gives one manifest per known instance. A
// manifest, count or for_each that can't be resolved leaves out only that
// resource, and is returned as a *terraformResourceError so the loader reports
// it, like a typed resource. references checks count and for_each for
// unresolved references, including ones hidden in locals.
func extractKubernetesManifests(body hcl.Body, evalCtx *hcl.EvalContext, references ...terraformReferenceChecker) ([]map[string]interface{}, []error) {
	manifests, errs := extractKubernetesManifestResources(body, evalCtx, references...)
	return terraformManifestObjects(manifests), errs
}

// extractKubernetesManifestResources is extractKubernetesManifests, keeping
// the source range of the kubernetes_manifest block each manifest came from.
func extractKubernetesManifestResources(body hcl.Body, evalCtx *hcl.EvalContext, references ...terraformReferenceChecker) ([]terraformManifest, []error) {
	var reference terraformReferenceChecker
	if len(references) > 0 {
		reference = references[0]
	}
	var errs []error
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
		},
	}
	content, _, _ := body.PartialContent(schema)

	var manifests []terraformManifest
	for _, block := range content.Blocks {
		if len(block.Labels) < 2 || block.Labels[0] != "kubernetes_manifest" {
			continue
		}
		attrSchema := &hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{{Name: "manifest"}, {Name: "count"}, {Name: "for_each"}},
		}
		attrContent, _, _ := block.Body.PartialContent(attrSchema)
		attr, ok := attrContent.Attributes["manifest"]
		if !ok {
			continue
		}
		var sourceSize int
		if synBody, ok := block.Body.(*hclsyntax.Body); ok {
			sourceSize = reference.sourceSize(synBody, synBody.SrcRange.End.Byte-synBody.SrcRange.Start.Byte)
		}
		path := "kubernetes_manifest." + block.Labels[1]
		instances, err := terraformResourceInstances(attrContent.Attributes["count"], attrContent.Attributes["for_each"],
			evalCtx, reference, path, sourceSize)
		if err != nil {
			errs = append(errs, &terraformResourceError{resource: path, err: err})
			continue
		}
		// Like a typed resource, the resource is left out when any of its
		// instances can't be resolved, so it is never reported as skipped
		// while part of it is scanned.
		var converted []terraformManifest
		unresolved := false
		for _, instanceCtx := range instances {
			val, diags := attr.Expr.Value(instanceCtx)
			if diags.HasErrors() {
				errs = append(errs, &terraformResourceError{resource: path, err: diags})
				unresolved = true
				continue
			}
			goVal := ctyToGo(val)
			m, ok := goVal.(map[string]interface{})
			if !ok {
				errs = append(errs, fmt.Errorf("resource %q: manifest is not an object", block.Labels[1]))
				continue
			}
			converted = append(converted, terraformManifest{object: m, source: block.DefRange})
		}
		if !unresolved {
			manifests = append(manifests, converted...)
		}
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

package cautils

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/zclconf/go-cty/cty"
)

const (
	// maxTerraformModuleDepth bounds how deep module calls are followed
	// from a root module.
	maxTerraformModuleDepth = 10
	// maxTerraformModuleCalls bounds how many module calls one Terraform
	// load follows, since count and for_each on nested calls multiply.
	maxTerraformModuleCalls = 1000
)

// terraformModuleMetaArguments are the arguments of a module block that are
// not inputs to the module.
var terraformModuleMetaArguments = map[string]bool{
	"source":     true,
	"version":    true,
	"count":      true,
	"for_each":   true,
	"providers":  true,
	"depends_on": true,
}

// terraformModuleInputs are the values a module block passes to the module's
// variables. Arguments whose value can't be resolved are listed in
// unresolved: the variable is left without a value rather than falling back
// to its default, which Terraform would not use.
type terraformModuleInputs struct {
	values     map[string]cty.Value
	unresolved map[string]bool
}

// terraformModuleCall is one instance of a module block with a local source.
type terraformModuleCall struct {
	name   string
	dir    string
	inputs terraformModuleInputs
}

// terraformLocalModuleDir returns the directory a module source points to
// when the source is a local path. Terraform only reads a source as a local
// path when it starts with "./" or "../"; anything else is a registry or
// remote address.
func terraformLocalModuleDir(callerDir string, source cty.Value) (string, bool) {
	if !source.IsKnown() || source.IsNull() || source.Type() != cty.String {
		return "", false
	}
	s := source.AsString()
	if !strings.HasPrefix(s, "./") && !strings.HasPrefix(s, "../") {
		return "", false
	}
	return filepath.Clean(filepath.Join(callerDir, filepath.FromSlash(s))), true
}

// collectTerraformModuleCalls returns the module blocks with a local source in
// files, with the value of each argument evaluated in the caller's context,
// once per count or for_each instance. A module block whose count or for_each
// can't be resolved is left out with a warning.
func collectTerraformModuleCalls(files []*hcl.File, dir string, evalCtx *hcl.EvalContext, references terraformReferenceChecker) []terraformModuleCall {
	schema := &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}
	var calls []terraformModuleCall
	for _, file := range files {
		content, _, _ := file.Body.PartialContent(schema)
		for _, block := range content.Blocks {
			body, ok := block.Body.(*hclsyntax.Body)
			if !ok {
				continue
			}
			source, ok := body.Attributes["source"]
			if !ok {
				continue
			}
			sourceVal, diags := source.Expr.Value(nil)
			if diags.HasErrors() {
				continue
			}
			moduleDir, ok := terraformLocalModuleDir(dir, sourceVal)
			if !ok {
				continue
			}
			name := "module." + block.Labels[0]
			var count, forEach *hcl.Attribute
			if attr, ok := body.Attributes["count"]; ok {
				count = attr.AsHCLAttribute()
			}
			if attr, ok := body.Attributes["for_each"]; ok {
				forEach = attr.AsHCLAttribute()
			}
			sourceSize := references.sourceSize(body, body.SrcRange.End.Byte-body.SrcRange.Start.Byte)
			instances, err := terraformResourceInstances(count, forEach, evalCtx, references, name, sourceSize)
			if err != nil {
				logger.L().Warning("Skipping Terraform module call with unresolved count or for_each",
					helpers.String("module", name), helpers.String("path", dir), helpers.Error(err))
				continue
			}
			for _, instanceCtx := range instances {
				inputs := terraformModuleInputs{values: map[string]cty.Value{}, unresolved: map[string]bool{}}
				for argName, attr := range body.Attributes {
					if terraformModuleMetaArguments[argName] {
						continue
					}
					if references.hasUnresolvableVariables(attr.Expr, instanceCtx) {
						inputs.unresolved[argName] = true
						continue
					}
					val, diags := attr.Expr.Value(instanceCtx)
					if diags.HasErrors() || !val.IsWhollyKnown() {
						inputs.unresolved[argName] = true
						continue
					}
					inputs.values[argName] = val
				}
				calls = append(calls, terraformModuleCall{name: name, dir: moduleDir, inputs: inputs})
			}
		}
	}
	return calls
}

// applyTerraformModuleInputs sets a module's variables from the values its
// caller passes, the way Terraform does: each value is converted to the
// variable's type, null gives the default for a non-nullable variable, and an
// argument the caller passes but that can't be resolved leaves the variable
// without a value. Arguments for undeclared variables are ignored.
func applyTerraformModuleInputs(inputs terraformModuleInputs, declared map[string]terraformVariable, values map[string]cty.Value) []error {
	var errs []error
	for name := range inputs.unresolved {
		delete(values, name)
	}
	for name, val := range inputs.values {
		variable, ok := declared[name]
		if !ok {
			continue
		}
		val, err := variable.convert(val)
		if err != nil {
			delete(values, name)
			errs = append(errs, fmt.Errorf("module input %q: %w", name, err))
			continue
		}
		if val.IsNull() && variable.nonNullable {
			if variable.defaultVal != cty.NilVal {
				values[name] = variable.defaultVal
			} else {
				delete(values, name)
				errs = append(errs, fmt.Errorf("module input %q: the variable is not nullable and has no default, so it may not be set to null", name))
			}
			continue
		}
		values[name] = val
	}
	return errs
}

// terraformModuleCallers returns, for each directory in dirs that a module
// block in another directory in dirs calls by a local source, the directories
// calling it. Like Terraform, only directories nothing calls are root
// modules; a called directory is scanned through its calls, with the values
// they pass. Override files are left out, as module blocks in them are not
// merged.
func terraformModuleCallers(dirs []string, workspaceDir string) map[string][]string {
	inDirs := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		inDirs[filepath.Clean(dir)] = true
	}
	parser := hclparse.NewParser()
	schema := &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}
	callers := map[string][]string{}
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if workspaceDir != "" && !pathcontainment.IsPathContained(workspaceDir, dir) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			f := filepath.Join(dir, entry.Name())
			if entry.IsDir() || !IsTerraformFile(f) || isTerraformOverrideFile(f) {
				continue
			}
			if workspaceDir != "" && !pathcontainment.IsPathContained(workspaceDir, f) {
				continue
			}
			content, err := readTerraformFile(f)
			if err != nil {
				continue
			}
			file, diags := parser.ParseHCL(content, f)
			if diags.HasErrors() {
				continue
			}
			blocks, _, _ := file.Body.PartialContent(schema)
			for _, block := range blocks.Blocks {
				attrs, _ := block.Body.JustAttributes()
				source, ok := attrs["source"]
				if !ok {
					continue
				}
				val, diags := source.Expr.Value(nil)
				if diags.HasErrors() {
					continue
				}
				moduleDir, ok := terraformLocalModuleDir(dir, val)
				if ok && moduleDir != dir && inDirs[moduleDir] && !slices.Contains(callers[moduleDir], dir) {
					callers[moduleDir] = append(callers[moduleDir], dir)
				}
			}
		}
	}
	return callers
}

// terraformModuleLoad is the state of one directory scan in
// LoadResourcesFromTerraformWithLocations: the root modules, and the local
// modules they call.
type terraformModuleLoad struct {
	ctx          context.Context
	workspaceDir string
	// root is the directory the scan was started on when it holds .tf files
	// itself. It is always scanned as a root module, as before, even when an
	// example below it calls it.
	root         string
	dirs         map[string]bool     // every Terraform directory found under the scan root
	callers      map[string][]string // directories another directory calls as a local module, with their callers
	rendered     map[string]bool     // called directories rendered through at least one call
	done         map[string]bool     // directories rendered, or tried, as a root or through a call
	calls        int
	limitWarned  bool
	locations    map[string]SourceLocation
	workloads    map[string][]workloadinterface.IMetadata
	skips        []SkippedManifest
	indexOffsets map[string]int
}

func newTerraformModuleLoad(ctx context.Context, dirs []string, root, workspaceDir string, locations map[string]SourceLocation) *terraformModuleLoad {
	l := &terraformModuleLoad{
		ctx:          ctx,
		workspaceDir: workspaceDir,
		dirs:         make(map[string]bool, len(dirs)),
		callers:      terraformModuleCallers(dirs, workspaceDir),
		rendered:     map[string]bool{},
		done:         map[string]bool{},
		locations:    locations,
		workloads:    map[string][]workloadinterface.IMetadata{},
		indexOffsets: map[string]int{},
	}
	if root != "" {
		l.root = filepath.Clean(root)
		delete(l.callers, l.root)
	}
	for _, dir := range dirs {
		l.dirs[filepath.Clean(dir)] = true
	}
	return l
}

// run renders every root module and the local modules it calls. A called
// module that no call rendered (its callers failed to render, every call
// failed to render, or a call's count or for_each could not be resolved or
// was empty) is still scanned on its own, as before, once all its callers
// have been tried, so a module is never scanned both on its own and through
// a call.
func (l *terraformModuleLoad) run(dirs []string) error {
	var pending []string
	for _, dir := range dirs {
		if len(l.callers[filepath.Clean(dir)]) > 0 {
			pending = append(pending, dir)
			continue
		}
		if err := l.renderRoot(dir, filepath.Clean(dir) == l.root); err != nil {
			return err
		}
	}
	for len(pending) > 0 {
		var next []string
		progress := false
		for _, dir := range pending {
			clean := filepath.Clean(dir)
			if l.rendered[clean] {
				progress = true
				continue
			}
			ready := true
			for _, caller := range l.callers[clean] {
				if !l.done[caller] {
					ready = false
					break
				}
			}
			if !ready {
				next = append(next, dir)
				continue
			}
			progress = true
			if err := l.renderRoot(dir, false); err != nil {
				return err
			}
		}
		if !progress {
			// Modules that only call each other: scan the first on its own.
			if err := l.renderRoot(next[0], false); err != nil {
				return err
			}
			next = next[1:]
		}
		pending = next
	}
	return nil
}

func (l *terraformModuleLoad) addWorkloads(wls map[string][]workloadinterface.IMetadata) {
	for src, list := range wls {
		l.workloads[src] = append(l.workloads[src], list...)
	}
}

// renderRoot renders dir as a root module, then the local modules it calls.
// explicit is true when dir is the directory the scan was started on, where a
// render error fails the scan instead of being skipped.
func (l *terraformModuleLoad) renderRoot(dir string, explicit bool) error {
	l.done[filepath.Clean(dir)] = true
	if l.workspaceDir != "" && !pathcontainment.IsPathContained(l.workspaceDir, dir) {
		if explicit {
			return fmt.Errorf("%w: Terraform directory %q outside workspace root", pathcontainment.ErrPathEscapesWorkspace, dir)
		}
		logger.L().Ctx(l.ctx).Warning("Skipping Terraform directory outside workspace root", helpers.String("path", dir))
		return nil
	}
	td := NewTerraformDirectory(dir, l.workspaceDir)
	td.indexOffsets = l.indexOffsets
	wls, dirErrs := td.GetWorkloads(dir)
	maps.Copy(l.locations, td.SourceLocations())
	if resources, ok := onlyTerraformResourceErrors(dirErrs); ok {
		// Only the resources that use values the scan can't resolve were
		// left out; the rest of the configuration is scanned.
		logTerraformUnresolvedResources(l.ctx, dir, resources, dirErrs)
		l.skips = append(l.skips, terraformUnresolvedResourcesSkip(dir, resources))
		dirErrs = nil
	}
	if len(dirErrs) > 0 {
		// Override blocks with no primary definition are skipped without
		// affecting the rest of the configuration, so the workloads it
		// defines are kept. The configuration error is still reported.
		// Resources left out for unresolved values may come with them; they
		// are reported as well instead of dropping the whole configuration.
		resources, resourceErrs, others := splitTerraformResourceErrors(dirErrs)
		overridesOnly := onlyTerraformMissingOverrideTargets(others)
		if explicit {
			if overridesOnly {
				l.addWorkloads(wls)
			}
			return fmt.Errorf("failed to render Terraform resources from %q: %w", dir, errors.Join(dirErrs...))
		}
		if !overridesOnly {
			logger.L().Ctx(l.ctx).Warning("Skipping nested Terraform configuration that failed to render", helpers.String("path", dir), helpers.Error(errors.Join(dirErrs...)))
			// HCL diagnostics contain source filenames and resource labels that
			// report anonymization cannot safely identify; keep them in logs.
			l.skips = append(l.skips, SkippedManifest{Path: dir, Reason: "failed to render Terraform configuration; see scan logs for details"})
			return nil
		}
		logger.L().Ctx(l.ctx).Warning("Nested Terraform configuration has override blocks that could not be applied; scanning the resources it defines without them",
			helpers.String("path", dir), helpers.Error(errors.Join(others...)))
		l.skips = append(l.skips, SkippedManifest{Path: dir, Reason: "some Terraform override blocks could not be applied; see scan logs for details"})
		if len(resources) > 0 {
			logTerraformUnresolvedResources(l.ctx, dir, resources, resourceErrs)
			l.skips = append(l.skips, terraformUnresolvedResourcesSkip(dir, resources))
		}
	}
	l.addWorkloads(wls)
	l.renderModuleCalls(td.moduleCalls, []string{filepath.Clean(dir)})
	return nil
}

// renderModuleCalls renders each local module call with the values it passes,
// then the calls inside that module. stack holds the modules on the way from
// the root, to stop a module that calls itself.
func (l *terraformModuleLoad) renderModuleCalls(calls []terraformModuleCall, stack []string) {
	for _, call := range calls {
		if !l.dirs[call.dir] || call.dir == l.root {
			// Not found under the scan root, excluded from the scan, or the
			// scan root itself, which is scanned on its own.
			continue
		}
		if slices.Contains(stack, call.dir) {
			logger.L().Ctx(l.ctx).Warning("Skipping Terraform module call that calls a module already being rendered", helpers.String("module", call.name), helpers.String("path", call.dir))
			continue
		}
		if len(stack) > maxTerraformModuleDepth || l.calls >= maxTerraformModuleCalls {
			if !l.limitWarned {
				l.limitWarned = true
				logger.L().Ctx(l.ctx).Warning("Skipping Terraform module calls: module nesting or call limit reached", helpers.String("module", call.name), helpers.String("path", call.dir))
				l.skips = append(l.skips, SkippedManifest{Path: call.dir, Reason: "Terraform module call limit reached; see scan logs for details"})
			}
			continue
		}
		l.calls++
		if l.workspaceDir != "" && !pathcontainment.IsPathContained(l.workspaceDir, call.dir) {
			logger.L().Ctx(l.ctx).Warning("Skipping Terraform directory outside workspace root", helpers.String("path", call.dir))
			continue
		}
		inputs := call.inputs
		td := NewTerraformDirectory(call.dir, l.workspaceDir)
		td.moduleInputs = &inputs
		td.indexOffsets = l.indexOffsets
		wls, errs := td.GetWorkloads(call.dir)
		if resources, ok := onlyTerraformResourceErrors(errs); ok {
			// As for a root module: only the resources that use a value the
			// call can't resolve are left out, not replaced by the defaults.
			logTerraformUnresolvedResources(l.ctx, call.dir, resources, errs)
			l.skips = append(l.skips, terraformUnresolvedResourcesSkip(call.dir, resources))
			errs = nil
		}
		resources, resourceErrs, others := splitTerraformResourceErrors(errs)
		if len(errs) > 0 && !onlyTerraformMissingOverrideTargets(others) {
			// The module is scanned on its own instead once its callers are
			// done, unless another call to it renders.
			logger.L().Ctx(l.ctx).Warning("Terraform module call failed to render; the module is scanned with its own defaults instead",
				helpers.String("module", call.name), helpers.String("path", call.dir), helpers.Error(errors.Join(errs...)))
			l.skips = append(l.skips, SkippedManifest{Path: call.dir, Reason: "failed to render Terraform module call; see scan logs for details"})
			continue
		}
		if len(errs) > 0 {
			logger.L().Ctx(l.ctx).Warning("Terraform module has override blocks that could not be applied; scanning the resources it defines without them",
				helpers.String("module", call.name), helpers.String("path", call.dir), helpers.Error(errors.Join(others...)))
			l.skips = append(l.skips, SkippedManifest{Path: call.dir, Reason: "some Terraform override blocks could not be applied; see scan logs for details"})
			if len(resources) > 0 {
				logTerraformUnresolvedResources(l.ctx, call.dir, resources, resourceErrs)
				l.skips = append(l.skips, terraformUnresolvedResourcesSkip(call.dir, resources))
			}
		}
		l.rendered[call.dir] = true
		l.done[call.dir] = true
		maps.Copy(l.locations, td.SourceLocations())
		l.addWorkloads(wls)
		l.renderModuleCalls(td.moduleCalls, append(slices.Clone(stack), call.dir))
	}
}

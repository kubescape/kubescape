package cautils

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// isTerraformOverrideFile reports whether path names a Terraform override
// file: override.tf or *_override.tf, matched as Terraform does on the file
// name without its extension. Terraform also accepts .tf.json override files,
// which, like other .tf.json files, are not read here.
func isTerraformOverrideFile(path string) bool {
	name := filepath.Base(path)
	if filepath.Ext(name) != ".tf" {
		return false
	}
	base := strings.TrimSuffix(name, ".tf")
	return base == "override" || strings.HasSuffix(base, "_override")
}

// terraformOverrideResult is the module configuration after override files
// were merged into the primary files.
type terraformOverrideResult struct {
	// files are the primary files, with the resource and local value
	// definitions that override files changed replaced by the merged ones.
	files []*hcl.File
	// variables are the override variable blocks that match a primary
	// declaration, in the order applyTerraformVariableOverrides applies them.
	variables []*hclsyntax.Block
	// sourceSizes holds the combined source size, in bytes, of the base and
	// override blocks a merged resource body was built from. A merged body
	// keeps its base block's source ranges, so they no longer measure how much
	// configuration it holds.
	sourceSizes map[*hclsyntax.Body]int
}

// terraformBlockPosition locates a top-level block in the merged primary
// files.
type terraformBlockPosition struct {
	file, block int
}

// terraformOverrideMerger applies override files to a copy of the primary
// files' top-level blocks.
type terraformOverrideMerger struct {
	bodies      []*hclsyntax.Body
	resources   map[string][]terraformBlockPosition
	variables   map[string][]terraformBlockPosition
	locals      map[string][]terraformBlockPosition
	sourceSizes map[*hclsyntax.Body]int

	variableOverrides []*hclsyntax.Block
}

// applyTerraformOverrides merges override files into the primary files the
// way Terraform does (https://developer.hashicorp.com/terraform/language/files/override),
// for the definitions that decide the Kubernetes objects Kubescape scans:
//
//   - a resource block replaces each argument of the primary resource block
//     with the same type and name that it sets, and its nested blocks replace
//     every nested block of the same type (a dynamic block counts as a block
//     of the type it generates); nested blocks are not merged further;
//   - a variable block overrides its default, type and nullable (see
//     applyTerraformVariableOverrides, which applies the blocks returned in
//     variables once the primary variables are collected);
//   - a local value replaces the primary local value with the same name.
//
// Override files are applied in the order given, after all primary files, so
// a later override file overrides an earlier one. An override with no primary
// definition to merge into is a configuration error in Terraform: it is
// reported and skipped, rather than read as a definition of its own. Other
// blocks in override files do not affect the Kubernetes objects and are not
// read. The parsed files are left unchanged.
func applyTerraformOverrides(primary, overrides []*hcl.File) (terraformOverrideResult, []error) {
	if len(overrides) == 0 {
		return terraformOverrideResult{files: primary}, nil
	}
	m := terraformOverrideMerger{
		bodies:      make([]*hclsyntax.Body, len(primary)),
		resources:   map[string][]terraformBlockPosition{},
		variables:   map[string][]terraformBlockPosition{},
		locals:      map[string][]terraformBlockPosition{},
		sourceSizes: map[*hclsyntax.Body]int{},
	}
	for i, file := range primary {
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		copied := *body
		copied.Blocks = slices.Clone(body.Blocks)
		m.bodies[i] = &copied
		m.index(i)
	}

	var errs []error
	for _, file := range overrides {
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			errs = append(errs, m.apply(block)...)
		}
	}

	files := make([]*hcl.File, len(primary))
	for i, file := range primary {
		if m.bodies[i] == nil {
			files[i] = file
			continue
		}
		files[i] = &hcl.File{Body: m.bodies[i], Bytes: file.Bytes, Nav: file.Nav}
	}
	return terraformOverrideResult{files: files, variables: m.variableOverrides, sourceSizes: m.sourceSizes}, errs
}

// applyTerraformVariableOverrides applies matching override variable blocks,
// in order, to the variables collected from the primary files, as Terraform's
// Variable.merge does:
//
//   - a default replaces the default; when the override also sets type, the
//     default is first converted to it, as Terraform does when decoding it;
//   - a type replaces the type constraint, but the optional attribute defaults
//     stay those of the primary declaration: Terraform's merge keeps them;
//   - nullable replaces nullable;
//   - the default in effect is then converted to the type constraint in effect.
//
// Other variable arguments and blocks, such as validation, are not merged by
// Terraform or do not change the value, and are not read. A default Terraform
// would reject, including a null default when nullable is false, leaves the
// variable without a default, as an invalid default in a primary file does.
// An invalid type constraint leaves the variable unset altogether, so that
// neither its default nor a variable file value is converted the wrong way.
func applyTerraformVariableOverrides(overrides []*hclsyntax.Block, defaults map[string]cty.Value, declared map[string]terraformVariable) {
	// stored is each overridden variable's default as Terraform keeps it in
	// the configuration, before the type's optional attribute defaults are
	// applied to it again when the value is used. For a primary declaration
	// this is the default collectVariableDefaults converted.
	stored := map[string]cty.Value{}
	for _, block := range overrides {
		name := block.Labels[0]
		variable, ok := declared[name]
		if !ok {
			continue
		}
		val, ok := stored[name]
		if !ok {
			val = variable.defaultVal
		}

		attrs := block.Body.Attributes
		typeAttr, typeSet := attrs["type"]
		var overrideType terraformVariable
		if typeSet {
			ty, tyDefaults, diags := typeexpr.TypeConstraintWithDefaults(typeAttr.Expr)
			if diags.HasErrors() {
				// Terraform rejects the configuration. Neither the default nor
				// a variable file value can be converted the way Terraform
				// would, so the variable is left unset and references to it
				// stay unresolved.
				logger.L().Warning("Ignoring Terraform variable with an invalid type constraint in an override file",
					helpers.String("variable", name), helpers.Error(diags))
				delete(declared, name)
				delete(defaults, name)
				continue
			}
			overrideType = terraformVariable{ty: ty, defaults: tyDefaults}
			variable.ty = ty
		}
		if attr, ok := attrs["nullable"]; ok {
			if nonNullable, ok := terraformVariableNonNullable(attr.AsHCLAttribute()); ok {
				variable.nonNullable = nonNullable
			}
		}
		if attr, ok := attrs["default"]; ok {
			var diags hcl.Diagnostics
			val, diags = attr.Expr.Value(nil)
			if diags.HasErrors() {
				val = cty.NilVal
			} else if typeSet {
				var err error
				if val, err = overrideType.convert(val); err != nil {
					val = cty.NilVal
				}
			}
		}
		if val != cty.NilVal {
			var err error
			if val, err = convert.Convert(val, variable.ty); err != nil {
				val = cty.NilVal
			}
		}
		// Terraform also rejects a null default once nullable is false.
		if val != cty.NilVal && val.IsNull() && variable.nonNullable {
			val = cty.NilVal
		}
		stored[name] = val

		delete(defaults, name)
		variable.defaultVal = cty.NilVal
		if val != cty.NilVal {
			if final, err := variable.convert(val); err == nil {
				defaults[name] = final
				variable.defaultVal = final
			}
		}
		declared[name] = variable
	}
}

// index records where the primary file's resource, variable and local value
// definitions are, so override blocks can be matched to them.
func (m *terraformOverrideMerger) index(file int) {
	for i, block := range m.bodies[file].Blocks {
		position := terraformBlockPosition{file: file, block: i}
		switch {
		case block.Type == "resource" && len(block.Labels) == 2:
			key := terraformResourceKey(block.Labels[0], block.Labels[1])
			m.resources[key] = append(m.resources[key], position)
		case block.Type == "variable" && len(block.Labels) == 1:
			m.variables[block.Labels[0]] = append(m.variables[block.Labels[0]], position)
		case block.Type == "locals" && len(block.Labels) == 0:
			for name := range block.Body.Attributes {
				m.locals[name] = append(m.locals[name], position)
			}
		}
	}
}

// apply merges one top-level block of an override file.
func (m *terraformOverrideMerger) apply(override *hclsyntax.Block) []error {
	switch {
	case override.Type == "resource" && len(override.Labels) == 2:
		positions := m.resources[terraformResourceKey(override.Labels[0], override.Labels[1])]
		if len(positions) == 0 {
			return []error{fmt.Errorf("%s: missing resource to override: there is no %s resource named %q; an override file can only override a resource block defined in a primary configuration file",
				override.DefRange(), override.Labels[0], override.Labels[1])}
		}
		for _, p := range positions {
			base := m.bodies[p.file].Blocks[p.block]
			merged := mergeTerraformBlock(base, override)
			m.sourceSizes[merged.Body] = m.blockSourceSize(base) + terraformBlockSpan(override)
			m.bodies[p.file].Blocks[p.block] = merged
		}
	case override.Type == "variable" && len(override.Labels) == 1:
		positions := m.variables[override.Labels[0]]
		if len(positions) == 0 {
			return []error{fmt.Errorf("%s: missing base variable declaration to override: there is no variable named %q; an override file can only override a variable that was already declared in a primary configuration file",
				override.DefRange(), override.Labels[0])}
		}
		m.variableOverrides = append(m.variableOverrides, override)
	case override.Type == "locals" && len(override.Labels) == 0:
		var errs []error
		// Apply in a stable order so that errors are reported deterministically.
		for _, name := range slices.Sorted(maps.Keys(override.Body.Attributes)) {
			attr := override.Body.Attributes[name]
			positions := m.locals[name]
			if len(positions) == 0 {
				errs = append(errs, fmt.Errorf("%s: missing base local value definition to override: there is no local value named %q; an override file can only override a local value that was already defined in a primary configuration file",
					attr.SrcRange, name))
				continue
			}
			for _, p := range positions {
				m.bodies[p.file].Blocks[p.block] = withTerraformAttribute(m.bodies[p.file].Blocks[p.block], attr)
			}
		}
		return errs
	}
	return nil
}

// blockSourceSize is the source size of a primary resource block, counting
// the override blocks already merged into it.
func (m *terraformOverrideMerger) blockSourceSize(block *hclsyntax.Block) int {
	if size, ok := m.sourceSizes[block.Body]; ok {
		return size
	}
	return terraformBlockSpan(block)
}

func terraformResourceKey(resourceType, name string) string {
	return resourceType + "." + name
}

func terraformBlockSpan(block *hclsyntax.Block) int {
	r := block.Range()
	return r.End.Byte - r.Start.Byte
}

// mergeTerraformBlock returns base with override's body merged into its own,
// keeping base's type, labels and source ranges.
func mergeTerraformBlock(base, override *hclsyntax.Block) *hclsyntax.Block {
	merged := *base
	merged.Body = mergeTerraformBody(base.Body, override.Body)
	return &merged
}

// mergeTerraformBody merges override into base as Terraform's MergeBodies
// does: an attribute in override replaces the attribute of the same name, and
// the blocks in override replace all of base's blocks of the same type. A
// dynamic block counts as a block of the type named by its label, both when
// it overrides and when it is overridden. Base's remaining blocks come first,
// followed by override's.
func mergeTerraformBody(base, override *hclsyntax.Body) *hclsyntax.Body {
	merged := *base
	merged.Attributes = make(hclsyntax.Attributes, len(base.Attributes)+len(override.Attributes))
	maps.Copy(merged.Attributes, base.Attributes)
	maps.Copy(merged.Attributes, override.Attributes)

	overridden := map[string]bool{}
	for _, block := range override.Blocks {
		overridden[terraformMergeBlockType(block)] = true
	}
	merged.Blocks = make(hclsyntax.Blocks, 0, len(base.Blocks)+len(override.Blocks))
	for _, block := range base.Blocks {
		if !overridden[terraformMergeBlockType(block)] {
			merged.Blocks = append(merged.Blocks, block)
		}
	}
	merged.Blocks = append(merged.Blocks, override.Blocks...)
	return &merged
}

// terraformMergeBlockType is the block type a nested block overrides, or is
// overridden by: a dynamic block stands for the blocks it generates.
func terraformMergeBlockType(block *hclsyntax.Block) string {
	if block.Type == "dynamic" && len(block.Labels) > 0 {
		return block.Labels[0]
	}
	return block.Type
}

// withTerraformAttribute returns a copy of block with attr replacing the
// attribute of the same name.
func withTerraformAttribute(block *hclsyntax.Block, attr *hclsyntax.Attribute) *hclsyntax.Block {
	body := *block.Body
	body.Attributes = maps.Clone(block.Body.Attributes)
	body.Attributes[attr.Name] = attr
	updated := *block
	updated.Body = &body
	return &updated
}

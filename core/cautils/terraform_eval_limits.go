package cautils

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Expressions in a scanned module are untrusted input, and several built-in
// functions can produce output far larger than their arguments (format pads to
// any requested width, indent repeats its padding on every line, join repeats
// its separator, and so on). Checking a local's size only after it has been
// evaluated is too late: the allocation has already happened. Every function
// call is therefore bounded before it runs:
//
//   - the combined size of its arguments must fit within the limit, which keeps
//     the output of functions that are linear in their input bounded;
//   - functions that can amplify their input estimate an upper bound of their
//     output from the arguments and refuse to run when it exceeds the limit;
//   - the size of the result is checked as a final safeguard.
const (
	// maxTerraformFunctionSize caps the size of the arguments and the result of
	// a single function call.
	maxTerraformFunctionSize = maxTerraformLocalSize
	// terraformElementOverhead approximates the memory used by each element of
	// a generated collection beyond the bytes of its content.
	terraformElementOverhead = 64
	// terraformEncodingExpansion is the worst-case growth of a value when it is
	// rendered as JSON (a control character becomes a six-byte \u escape).
	terraformEncodingExpansion = 6
)

// terraformOutputBound estimates an upper bound of a function's output size
// from its (known) arguments, saturating above limit.
type terraformOutputBound func(args []cty.Value, limit int) (int, error)

// terraformFunctionBounds lists the functions whose output can grow faster
// than the size of their arguments.
var terraformFunctionBounds = map[string]terraformOutputBound{
	"format":     formatOutputBound,
	"formatlist": formatListOutputBound,
	"indent":     indentOutputBound,
	"join":       joinOutputBound,
	"regexall":   regexAllOutputBound,
	"replace":    replaceOutputBound,
	"split":      splitOutputBound,
}

// terraformFunctions are the functions available to Terraform expressions.
var terraformFunctions = boundTerraformFunctions(unboundedTerraformFunctions, maxTerraformFunctionSize)

func boundTerraformFunctions(funcs map[string]function.Function, limit int) map[string]function.Function {
	bounded := make(map[string]function.Function, len(funcs))
	for name, fn := range funcs {
		switch name {
		case "can", "try":
			// These take unevaluated expressions; every function those
			// expressions call is bounded on its own.
			bounded[name] = fn
		default:
			bounded[name] = boundTerraformFunction(name, fn, terraformFunctionBounds[name], limit)
		}
	}
	return bounded
}

func boundTerraformFunction(name string, fn function.Function, bound terraformOutputBound, limit int) function.Function {
	return function.New(&function.Spec{
		Description: fn.Description(),
		Params:      fn.Params(),
		VarParam:    fn.VarParam(),
		Type:        fn.ReturnTypeForValues,
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			size := 0
			for _, arg := range args {
				size = saturatingAdd(size, terraformValueSize(arg, limit-size), limit)
			}
			if size > limit {
				return cty.UnknownVal(retType), fmt.Errorf("%s: arguments exceed the size limit of %d bytes", name, limit)
			}
			if bound != nil {
				estimate, err := bound(args, limit)
				if err != nil {
					return cty.UnknownVal(retType), err
				}
				if estimate > limit {
					return cty.UnknownVal(retType), fmt.Errorf("%s: result would exceed the size limit of %d bytes", name, limit)
				}
			}
			val, err := fn.Call(args)
			if err != nil {
				return val, err
			}
			if terraformValueSize(val, limit) > limit {
				return cty.UnknownVal(retType), fmt.Errorf("%s: result exceeds the size limit of %d bytes", name, limit)
			}
			return val, nil
		},
	})
}

// saturatingAdd returns a+b, or limit+1 when the sum exceeds limit, so that
// estimates never overflow.
func saturatingAdd(a, b, limit int) int {
	if a > limit || b > limit || a+b > limit {
		return limit + 1
	}
	return a + b
}

func saturatingMul(a, b, limit int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > limit/b {
		return limit + 1
	}
	return a * b
}

// terraformNumberSize approximates the length of a number's decimal
// representation, which for very large or very small exponents (1e100000000)
// is far larger than the literal that produced it.
func terraformNumberSize(val cty.Value) int {
	bf := val.AsBigFloat()
	if bf.IsInf() {
		return 4
	}
	exp := bf.MantExp(nil)
	if exp < 0 {
		exp = -exp
	}
	// log10(2) ≈ 0.30103; add room for sign, point and the mantissa digits.
	return 160 + int(float64(exp)*0.30103)
}

// formatVerbSpec is one verb of a format string, following the grammar of
// go-cty's format function: '%' flags width ['.' precision] ['[' argnum ']'] mode.
type formatVerbSpec struct {
	sharp       bool
	width, prec int
	argNum      int
	mode        byte
}

// parseFormatVerbs returns the verbs and the number of literal bytes of a
// format string. Widths and precisions saturate above limit. Malformed format
// strings are reported by go-cty itself when the function runs, so parsing
// simply stops at the first unexpected byte.
func parseFormatVerbs(format string, limit int) ([]formatVerbSpec, int) {
	var verbs []formatVerbSpec
	literal := 0
	nextArg := 1
	readNum := func(i int) (int, int) {
		n := 0
		for ; i < len(format) && format[i] >= '0' && format[i] <= '9'; i++ {
			n = saturatingAdd(saturatingMul(n, 10, limit), int(format[i]-'0'), limit)
		}
		return n, i
	}
	for i := 0; i < len(format); {
		if format[i] != '%' {
			literal++
			i++
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			literal++
			i += 2
			continue
		}
		verb := formatVerbSpec{argNum: nextArg}
		i++
		for ; i < len(format) && strings.IndexByte("0#-+ ", format[i]) >= 0; i++ {
			verb.sharp = verb.sharp || format[i] == '#'
		}
		verb.width, i = readNum(i)
		if i < len(format) && format[i] == '.' {
			verb.prec, i = readNum(i + 1)
		}
		if i < len(format) && format[i] == '[' {
			verb.argNum, i = readNum(i + 1)
			if i >= len(format) || format[i] != ']' {
				return verbs, literal
			}
			i++
		}
		if i >= len(format) || !(format[i] >= 'a' && format[i] <= 'z' || format[i] >= 'A' && format[i] <= 'Z') {
			return verbs, literal
		}
		verb.mode = format[i]
		i++
		verbs = append(verbs, verb)
		nextArg = verb.argNum + 1
	}
	return verbs, literal
}

// formattedValueSize bounds the size of one value rendered by a format verb.
func formattedValueSize(verb formatVerbSpec, val cty.Value, limit int) int {
	switch {
	case val.IsNull() || !val.IsKnown():
		return 8
	case val.Type() == cty.String && (verb.mode == 's' || verb.mode == 'v' && !verb.sharp):
		return len(val.AsString())
	case val.Type() == cty.Number:
		return terraformNumberSize(val)
	default:
		return saturatingMul(terraformValueSize(val, limit), terraformEncodingExpansion, limit)
	}
}

func formatOutputBoundFor(format string, argSize func(verb formatVerbSpec) int, limit int) int {
	verbs, total := parseFormatVerbs(format, limit)
	for _, verb := range verbs {
		// Width pads, precision adds digits after the point; both are counted
		// on top of the value itself to stay an upper bound.
		total = saturatingAdd(total, verb.width, limit)
		total = saturatingAdd(total, verb.prec, limit)
		total = saturatingAdd(total, argSize(verb), limit)
	}
	return total
}

func formatOutputBound(args []cty.Value, limit int) (int, error) {
	format, rest := args[0].AsString(), args[1:]
	return formatOutputBoundFor(format, func(verb formatVerbSpec) int {
		if verb.argNum < 1 || verb.argNum > len(rest) {
			return 0
		}
		return formattedValueSize(verb, rest[verb.argNum-1], limit)
	}, limit), nil
}

func formatListOutputBound(args []cty.Value, limit int) (int, error) {
	format, rest := args[0].AsString(), args[1:]
	iterations := 1
	for _, arg := range rest {
		if ty := arg.Type(); arg.IsKnown() && !arg.IsNull() && (ty.IsListType() || ty.IsTupleType() || ty.IsSetType()) {
			iterations = max(iterations, arg.LengthInt())
		}
	}
	perIteration := formatOutputBoundFor(format, func(verb formatVerbSpec) int {
		if verb.argNum < 1 || verb.argNum > len(rest) {
			return 0
		}
		arg := rest[verb.argNum-1]
		if ty := arg.Type(); !arg.IsKnown() || arg.IsNull() || !(ty.IsListType() || ty.IsTupleType() || ty.IsSetType()) {
			return formattedValueSize(verb, arg, limit)
		}
		largest := 0
		for it := arg.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			largest = max(largest, formattedValueSize(verb, elem, limit))
		}
		return largest
	}, limit)
	return saturatingMul(saturatingAdd(perIteration, terraformElementOverhead, limit), iterations, limit), nil
}

func indentOutputBound(args []cty.Value, limit int) (int, error) {
	bf := args[0].AsBigFloat()
	if bf.Sign() < 0 {
		return 0, fmt.Errorf("indent: number of spaces must not be negative")
	}
	spaces := limit + 1
	if bf.IsInt() {
		if n, _ := bf.Int64(); n <= int64(limit) {
			spaces = int(n)
		}
	}
	str := args[1].AsString()
	return saturatingAdd(len(str), saturatingMul(strings.Count(str, "\n"), spaces, limit), limit), nil
}

func joinOutputBound(args []cty.Value, limit int) (int, error) {
	sep := len(args[0].AsString())
	total, elems := 0, 0
	for _, list := range args[1:] {
		if !list.IsKnown() || list.IsNull() {
			continue
		}
		for it := list.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			elems++
			if elem.IsKnown() && !elem.IsNull() && elem.Type() == cty.String {
				total = saturatingAdd(total, len(elem.AsString()), limit)
			}
		}
	}
	if elems > 1 {
		total = saturatingAdd(total, saturatingMul(sep, elems-1, limit), limit)
	}
	return total, nil
}

func splitOutputBound(args []cty.Value, limit int) (int, error) {
	sep, str := args[0].AsString(), args[1].AsString()
	parts := utf8.RuneCountInString(str) + 1
	if sep != "" {
		parts = strings.Count(str, sep) + 1
	}
	return saturatingAdd(len(str), saturatingMul(parts, terraformElementOverhead, limit), limit), nil
}

func regexAllOutputBound(args []cty.Value, limit int) (int, error) {
	re, err := regexp.Compile(args[0].AsString())
	if err != nil {
		// Reported by the function itself.
		return 0, nil
	}
	str := args[1].AsString()
	perMatch := terraformElementOverhead * (re.NumSubexp() + 1)
	maxMatches := limit/perMatch + 1
	matches := re.FindAllStringIndex(str, maxMatches+1)
	return saturatingAdd(len(str), saturatingMul(len(matches), perMatch, limit), limit), nil
}

// replaceOutputBound bounds both forms of replace: a literal substring, and a
// /regex/ whose replacement may expand $1-style references to submatches.
func replaceOutputBound(args []cty.Value, limit int) (int, error) {
	str, substr, repl := args[0].AsString(), args[1].AsString(), args[2].AsString()
	if len(substr) > 1 && strings.HasPrefix(substr, "/") && strings.HasSuffix(substr, "/") {
		re, err := regexp.Compile(substr[1 : len(substr)-1])
		if err != nil {
			return 0, nil
		}
		// Every match is replaced by repl, in which each '$' reference expands
		// to at most the length of the match it refers to.
		matches := re.FindAllStringIndex(str, -1)
		longest := 0
		for _, m := range matches {
			longest = max(longest, m[1]-m[0])
		}
		perMatch := saturatingAdd(len(repl), saturatingMul(strings.Count(repl, "$"), longest, limit), limit)
		return saturatingAdd(len(str), saturatingMul(len(matches), perMatch, limit), limit), nil
	}
	count := utf8.RuneCountInString(str) + 1
	if substr != "" {
		count = strings.Count(str, substr)
	}
	return saturatingAdd(len(str), saturatingMul(count, len(repl), limit), limit), nil
}

package cautils

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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

// boundTerraformFunction wraps fn so that oversized calls are refused before
// any work proportional to the output is done.
//
// HCL converts arguments to the declared parameter types before calling a
// function, and go-cty computes the return type before running it. Both steps
// can allocate in proportion to the result (rendering 1e500000000 as a string
// for upper, building the tuple type of a concat of many large tuples), so the
// wrapper declares every parameter as dynamic, checks the size of the raw
// arguments while computing the return type, and only then converts the
// arguments itself and delegates to fn.
func boundTerraformFunction(name string, fn function.Function, bound terraformOutputBound, limit int) function.Function {
	params := fn.Params()
	varParam := fn.VarParam()
	paramType := func(i int) cty.Type {
		if i < len(params) {
			return params[i].Type
		}
		return varParam.Type
	}
	dynamic := func(p function.Parameter) function.Parameter {
		p.Type = cty.DynamicPseudoType
		p.AllowDynamicType = true
		return p
	}
	spec := &function.Spec{
		Description: fn.Description(),
		Params:      make([]function.Parameter, len(params)),
	}
	for i, p := range params {
		spec.Params[i] = dynamic(p)
	}
	if varParam != nil {
		vp := dynamic(*varParam)
		spec.VarParam = &vp
	}
	checkArgs := func(args []cty.Value) error {
		size := 0
		for _, arg := range args {
			size = saturatingAdd(size, terraformValueSize(arg, limit-size), limit)
		}
		if size > limit {
			return fmt.Errorf("%s: arguments exceed the size limit of %d bytes", name, limit)
		}
		return nil
	}
	// convertArgs performs the conversion HCL would otherwise have done. It
	// only runs after checkArgs, and terraformValueSize counts numbers by their
	// decimal length, so producing the converted values is bounded by the
	// limit. The converted values are checked again before they are returned:
	// a conversion can turn a short value into one that is expensive to
	// operate on, such as the string "1e500000000" into a number whose integer
	// part has 500 million digits, which ceil or floor would then materialize.
	convertArgs := func(args []cty.Value) ([]cty.Value, error) {
		if err := checkArgs(args); err != nil {
			return nil, err
		}
		converted := make([]cty.Value, len(args))
		for i, arg := range args {
			ty := paramType(i)
			if ty == cty.DynamicPseudoType {
				converted[i] = arg
				continue
			}
			val, err := convert.Convert(arg, ty)
			if err != nil {
				return nil, function.NewArgError(i, err)
			}
			converted[i] = val
		}
		if err := checkArgs(converted); err != nil {
			return nil, err
		}
		return converted, nil
	}
	spec.Type = func(args []cty.Value) (cty.Type, error) {
		converted, err := convertArgs(args)
		if err != nil {
			return cty.NilType, err
		}
		return fn.ReturnTypeForValues(converted)
	}
	spec.Impl = func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		converted, err := convertArgs(args)
		if err != nil {
			return cty.UnknownVal(retType), err
		}
		if bound != nil {
			estimate, err := bound(converted, limit)
			if err != nil {
				return cty.UnknownVal(retType), err
			}
			if estimate > limit {
				return cty.UnknownVal(retType), fmt.Errorf("%s: result would exceed the size limit of %d bytes", name, limit)
			}
		}
		val, err := fn.Call(converted)
		if err != nil {
			return cty.UnknownVal(retType), err
		}
		if terraformValueSize(val, limit) > limit {
			return cty.UnknownVal(retType), fmt.Errorf("%s: result exceeds the size limit of %d bytes", name, limit)
		}
		return val, nil
	}
	return function.New(spec)
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
	return terraformNumberSizeInBase(val, math.Log2(10))
}

// terraformNumberSizeInBase approximates the length of a number written with
// digits that each carry bitsPerDigit bits (1 for binary, 4 for hex, log2(10)
// for decimal).
func terraformNumberSizeInBase(val cty.Value, bitsPerDigit float64) int {
	bf := val.AsBigFloat()
	if bf.IsInf() {
		return 4
	}
	exp := bf.MantExp(nil)
	if exp < 0 {
		exp = -exp
	}
	// Add room for the sign, the point and the digits of the 512-bit mantissa.
	return 160 + int(float64(exp)/bitsPerDigit)
}

func isASCIILetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isSequenceType(ty cty.Type) bool {
	return ty.IsListType() || ty.IsTupleType() || ty.IsSetType()
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
		if i >= len(format) || !isASCIILetter(format[i]) {
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
	if val.IsNull() || !val.IsKnown() {
		return 8
	}
	if bitsPerDigit, numeric := formatNumericVerbs[verb.mode]; numeric {
		// go-cty converts the argument to a number before formatting it, so a
		// short string such as "1e500000000" can expand to a huge integer.
		// Parsing the number is cheap; its rendering is what must be bounded.
		num, err := convert.Convert(val, cty.Number)
		if err != nil || num.IsNull() || !num.IsKnown() {
			// Reported by the function itself.
			return 8
		}
		return terraformNumberSizeInBase(num, bitsPerDigit)
	}
	switch {
	case val.Type() == cty.String && (verb.mode == 's' || verb.mode == 'v' && !verb.sharp):
		return len(val.AsString())
	case val.Type() == cty.Number:
		return terraformNumberSize(val)
	default:
		return saturatingMul(terraformValueSize(val, limit), terraformEncodingExpansion, limit)
	}
}

// formatNumericVerbs are the verbs for which go-cty converts the argument to a
// number, with the number of bits carried by each digit they print. Decimal is
// used for the floating-point verbs, which can print every integer digit.
var formatNumericVerbs = map[byte]float64{
	'b': 1, 'o': 3, 'x': 4, 'X': 4,
	'd': math.Log2(10), 'e': math.Log2(10), 'E': math.Log2(10),
	'f': math.Log2(10), 'g': math.Log2(10), 'G': math.Log2(10),
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
		if arg.IsKnown() && !arg.IsNull() && isSequenceType(arg.Type()) {
			iterations = max(iterations, arg.LengthInt())
		}
	}
	perIteration := formatOutputBoundFor(format, func(verb formatVerbSpec) int {
		if verb.argNum < 1 || verb.argNum > len(rest) {
			return 0
		}
		arg := rest[verb.argNum-1]
		if !arg.IsKnown() || arg.IsNull() || !isSequenceType(arg.Type()) {
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
	// go-cty builds the padding string before looking for newlines, so the
	// padding is allocated even when the input has none.
	str := args[1].AsString()
	padded := saturatingMul(strings.Count(str, "\n"), spaces, limit)
	return saturatingAdd(saturatingAdd(len(str), spaces, limit), padded, limit), nil
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

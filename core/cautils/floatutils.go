package cautils

import (
	"math"
	"strconv"
)

const floorEpsilon = 1e-4

// Float64ToInt convert float64 to int
func Float64ToInt(x float64) int {
	return int(math.Round(x))
}

// Float32ToInt convert float32 to int
func Float32ToInt(x float32) int {
	return Float64ToInt(float64(x))
}

// Float32ToIntFloor converts float32 to int by flooring. float32 representation
// error can make float32(53)/float32(100)*100 evaluate to 52.999996, so values
// within epsilon of an integer snap to that integer first. This is a deliberate
// exception to flooring: a value just below an integer can snap up to it.
// The snap only applies to non-negative values; negative inputs retain standard
// math.Floor semantics.
func Float32ToIntFloor(x float32) int {
	f := float64(x)
	if r := math.Round(f); f >= 0 && math.Abs(f-r) < floorEpsilon {
		return int(r)
	}
	return int(math.Floor(f))
}

// ComplianceScoreToInt converts a compliance score to a display-safe integer.
// It preserves the existing rounded display for ordinary scores while ensuring
// a score below 100 never appears perfect because of rounding.
func ComplianceScoreToInt(x float32) int {
	i := Float32ToInt(x)
	if i >= 100 && x < 100 {
		return 99
	}
	return i
}

// ComplianceScoreToString formats a compliance score for display with the given
// precision, ensuring a score below 100 never renders as perfect.
func ComplianceScoreToString(x float32, precision int) string {
	s := strconv.FormatFloat(float64(x), 'f', precision, 32)
	if x < 100 {
		if v, err := strconv.ParseFloat(s, 64); err == nil && v >= 100 {
			return strconv.FormatFloat(100-math.Pow10(-precision), 'f', precision, 64)
		}
	}
	return s
}

// RiskScoreToInt converts a risk score to a display-safe integer. It preserves
// the existing rounded display while ensuring a non-zero risk never appears as
// zero because of rounding.
func RiskScoreToInt(x float32) int {
	i := Float32ToInt(x)
	if i <= 0 && x > 0 {
		return 1
	}
	return i
}

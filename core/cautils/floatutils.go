package cautils

import "math"

// Float64ToInt convert float64 to int
func Float64ToInt(x float64) int {
	return int(math.Round(x))
}

// Float32ToInt convert float32 to int
func Float32ToInt(x float32) int {
	return Float64ToInt(float64(x))
}

// Float16ToInt convert float16 to int
func Float16ToInt(x float32) int {
	return Float64ToInt(float64(x))
}

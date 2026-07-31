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

// Float32ToIntFloor converts float32 to int by flooring, so a value never rounds up
func Float32ToIntFloor(x float32) int {
	return int(math.Floor(float64(x)))
}

// Float32ToIntComplianceScore converts a compliance score to int so a non-perfect score never displays as 100
func Float32ToIntComplianceScore(score float32) int {
	if score >= 100 {
		return 100
	}
	if score > 99 {
		return 99
	}
	return Float32ToInt(score)
}

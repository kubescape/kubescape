package cautils

import "github.com/kubescape/opa-utils/reporthandling"

func IsSubSliceScanningScopeType(haystack []reporthandling.ScanningScopeType, needle []reporthandling.ScanningScopeType) bool {
	ret := false
	if len(needle) > len(haystack) {
		return ret
	}
	for i := range haystack {
		if i+len(needle) > len(haystack) {
			break
		}
		match_len := 0
		for j := range needle {
			if needle[j] != haystack[i+j] {
				break
			}
			match_len += 1
		}
		if match_len == len(needle) {
			ret = true
			break
		}
	}
	return ret
}

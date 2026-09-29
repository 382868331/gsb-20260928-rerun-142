package license

import (
	"strconv"
	"strings"
)

// compareSemver compares dotted numeric versions. Missing components count as
// zero, so "1.2" equals "1.2.0". Non-numeric input is compared as 0.
func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = atoiOrZero(pa[i])
		}
		if i < len(pb) {
			vb = atoiOrZero(pb[i])
		}
		if va != vb {
			if va < vb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiOrZero(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return v
}

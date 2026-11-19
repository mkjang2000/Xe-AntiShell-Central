package githubrelease

import (
	"cmp"
	"regexp"
	"strings"
)

var packageTagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})-r([1-9][0-9]{0,8})$`)

// ComparePackageTags orders vVERSION-rRELEASE tags by their numeric components.
// Other tags sort below package tags and compare equal to each other.
func ComparePackageTags(a, b string) int {
	x, y := packageTagPattern.FindStringSubmatch(a), packageTagPattern.FindStringSubmatch(b)
	if x == nil || y == nil {
		return cmp.Compare(len(x), len(y))
	}
	for i := 1; i < len(x); i++ {
		if order := cmp.Compare(len(x[i]), len(y[i])); order != 0 {
			return order
		}
		if order := strings.Compare(x[i], y[i]); order != 0 {
			return order
		}
	}
	return 0
}

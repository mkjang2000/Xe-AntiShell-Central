package central

import (
	"io"
	"strings"
	"testing"
)

func TestUpdateRPMMetadataAndOutputAreBounded(t *testing.T) {
	valid := "xe-antishell\n0\n0.1.0\n24.el9\nx86_64\n"
	pack, major, err := parseUpdateRPMQuery(valid)
	if err != nil || pack != updatePackage(24) || major != "9" {
		t.Fatalf("valid metadata: %v", err)
	}
	if _, major, err := parseUpdateRPMQuery(strings.Replace(valid, "24.el9", "24.el9_8", 1)); err != nil || major != "9" {
		t.Fatal("EL point release suffix rejected")
	}
	for _, bad := range []string{
		strings.Replace(valid, "xe-antishell\n", "xe-antishell-central\n", 1), strings.Replace(valid, "x86_64", "noarch", 1),
		strings.Replace(valid, "24.el9", "24.el99", 1), strings.Replace(valid, "0\n", "-1\n", 1), valid + "extra\n", strings.Replace(valid, "0.1.0", "invalid\nvalue", 1),
	} {
		if _, _, err := parseUpdateRPMQuery(bad); err == nil {
			t.Fatal("invalid RPM metadata accepted")
		}
	}
	var output rpmQueryOutput
	if _, err = output.Write([]byte(strings.Repeat("x", 4097))); err == nil || output.Len() != 0 {
		t.Fatal("unbounded metadata output")
	}
	if _, err = io.Copy(&output, io.LimitReader(strings.NewReader(strings.Repeat("x", 4097)), 4097)); err == nil || output.Len() > 4096 {
		t.Fatal("io.Copy bypassed query output cap")
	}
}

func TestUpdateRPMOrderingUsesRPMRunsNotStringsOrSemver(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want int
	}{
		{"1.9", "1.10", -1}, {"1.0~rc1", "1.0", -1}, {"1.0", "1.0^git1", -1}, {"1.0^git1", "1.0.1", -1},
		{"1.0", "1.00", 0}, {"1.0a", "1.0.1", -1}, {"1+0", "1.0", 0}, {"2", "1.99", 1},
	} {
		if got := compareRPMComponent(test.a, test.b); got != test.want {
			t.Fatalf("RPM compare %s %s=%d want%d", test.a, test.b, got, test.want)
		}
	}
	a, b := updatePackage(9), updatePackage(10)
	if compareUpdatePackage(a, b) >= 0 {
		t.Fatal("numeric release compared lexically")
	}
	a.Epoch = 2
	b.Epoch = 1
	b.Version = "999"
	if compareUpdatePackage(a, b) <= 0 {
		t.Fatal("epoch ignored")
	}
}

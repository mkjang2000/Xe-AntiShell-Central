package central

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

var updateDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type rpmQueryOutput struct{ body bytes.Buffer }

func (b *rpmQueryOutput) Len() int       { return b.body.Len() }
func (b *rpmQueryOutput) String() string { return b.body.String() }

func (b *rpmQueryOutput) Write(value []byte) (int, error) {
	if b.Len()+len(value) > 4096 {
		return 0, errors.New("RPM query output exceeds limit")
	}
	return b.body.Write(value)
}

func inspectUpdateRPM(ctx context.Context, filename string) (managed.RPMPackage, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/rpm", "--query", "--package", "--queryformat", "%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", filename)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output rpmQueryOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil {
		return managed.RPMPackage{}, "", ErrInvalid
	}
	return parseUpdateRPMQuery(output.String())
}

func parseUpdateRPMQuery(output string) (managed.RPMPackage, string, error) {
	pack, major, err := managed.ParseRPMMetadata([]byte(output))
	if err != nil {
		return managed.RPMPackage{}, "", ErrInvalid
	}
	return pack, major, nil
}

// RPM compares epoch, then version and release using numeric/alphabetic runs.
// Tilde sorts before every run; caret sorts after an ended version but before
// the next run. Inputs have already passed the bounded RPM component validator.
func compareUpdatePackage(a, b managed.RPMPackage) int {
	if a.Epoch < b.Epoch {
		return -1
	}
	if a.Epoch > b.Epoch {
		return 1
	}
	if value := compareRPMComponent(a.Version, b.Version); value != 0 {
		return value
	}
	return compareRPMComponent(a.Release, b.Release)
}
func rpmAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func rpmDigit(c byte) bool { return c >= '0' && c <= '9' }
func rpmRun(c byte) bool   { return rpmAlpha(c) || rpmDigit(c) }
func compareRPMComponent(a, b string) int {
	for a != "" || b != "" {
		for len(a) > 0 && !rpmRun(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !rpmRun(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			if !strings.HasPrefix(a, "~") {
				return 1
			}
			if !strings.HasPrefix(b, "~") {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		if strings.HasPrefix(a, "^") || strings.HasPrefix(b, "^") {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !strings.HasPrefix(a, "^") {
				return 1
			}
			if !strings.HasPrefix(b, "^") {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := rpmDigit(a[0])
		i, j := 0, 0
		for i < len(a) && rpmDigit(a[i]) == numeric && rpmRun(a[i]) {
			i++
		}
		for j < len(b) && rpmDigit(b[j]) == numeric && rpmRun(b[j]) {
			j++
		}
		if j == 0 {
			if numeric {
				return 1
			}
			return -1
		}
		x, y := a[:i], b[:j]
		if numeric {
			x = strings.TrimLeft(x, "0")
			y = strings.TrimLeft(y, "0")
			if len(x) < len(y) {
				return -1
			}
			if len(x) > len(y) {
				return 1
			}
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
		a = a[i:]
		b = b[j:]
	}
	if a != "" {
		return 1
	}
	if b != "" {
		return -1
	}
	return 0
}

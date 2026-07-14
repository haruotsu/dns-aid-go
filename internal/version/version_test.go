package version

import (
	"regexp"
	"strings"
	"testing"
)

// semverPattern matches a bare SemVer core (no leading "v"), which is what
// tagpr writes into Version as the single source of truth.
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func TestVersionIsSemVer(t *testing.T) {
	if !semverPattern.MatchString(Version) {
		t.Errorf("Version = %q, want a bare SemVer core like 1.2.3", Version)
	}
}

// N-6 requires the conformant draft revision (not just the draft name) to be
// identifiable from a release, so DraftVersion must carry the -NN suffix.
func TestDraftVersion(t *testing.T) {
	const want = "draft-mozleywilliams-dnsop-dnsaid-02"
	if DraftVersion != want {
		t.Errorf("DraftVersion = %q, want %q", DraftVersion, want)
	}
}

func TestStringIncludesVersionAndDraft(t *testing.T) {
	s := String()
	if !strings.Contains(s, Version) {
		t.Errorf("String() = %q, does not contain Version %q", s, Version)
	}
	if !strings.Contains(s, DraftVersion) {
		t.Errorf("String() = %q, does not contain DraftVersion %q", s, DraftVersion)
	}
}

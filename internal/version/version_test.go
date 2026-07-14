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
// The revision digits themselves are not asserted: bumping them is exactly
// the change this constant exists for.
var draftPattern = regexp.MustCompile(`^draft-mozleywilliams-dnsop-dnsaid-\d{2}$`)

func TestDraftVersionCarriesRevision(t *testing.T) {
	if !draftPattern.MatchString(DraftVersion) {
		t.Errorf("DraftVersion = %q, want the draft name with a -NN revision suffix", DraftVersion)
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

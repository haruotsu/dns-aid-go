// Package version is the single source of truth for the dns-aid-go release
// version and the IETF draft it conforms to.
//
// Version is managed by tagpr (see .tagpr and .github/workflows/tagpr.yml);
// do not edit it by hand. The release PR that tagpr opens bumps this constant,
// and merging that PR creates the corresponding tag.
package version

import "fmt"

// Version is the current release version as a bare SemVer core (no leading
// "v"). tagpr rewrites this constant; treat it as the single source of truth.
const Version = "0.0.0"

// DraftVersion is the IETF draft this implementation conforms to. Record any
// change here in the release notes when the draft is revised (requirement N-6).
const DraftVersion = "draft-mozleywilliams-dnsop-dnsaid"

// String returns a human-readable version line including the conformant draft,
// suitable for the `dnsaid version` command.
func String() string {
	return fmt.Sprintf("%s (conforms to %s)", Version, DraftVersion)
}

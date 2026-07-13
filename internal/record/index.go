// Package record implements pure encode/decode functions for the DNS records
// defined by draft-mozleywilliams-dnsop-dnsaid: the domain index TXT record
// and the SVCB custom parameters. It performs no I/O.
package record

import (
	"fmt"
	"strings"
)

// indexPrefix is the key/value prefix of the domain index TXT record,
// e.g. "agents=chat:mcp,billing:a2a".
const indexPrefix = "agents="

// IndexEntry is one agent entry in the domain index TXT record.
type IndexEntry struct {
	// Name is the agent name, the DNS label prefixed to the domain
	// (e.g. "chat" for chat.example.com).
	Name string
	// Protocol is the agent protocol identifier (e.g. "mcp", "a2a").
	Protocol string
}

// ParseIndexTXT parses the domain index TXT record value
// ("agents=name:proto,...") into index entries.
//
// Multiple arguments are concatenated before parsing, matching how a DNS TXT
// record consisting of multiple character-strings is interpreted (RFC 1035).
func ParseIndexTXT(txts ...string) ([]IndexEntry, error) {
	txt := strings.TrimSpace(strings.Join(txts, ""))
	if txt == "" {
		return nil, fmt.Errorf("empty index TXT record")
	}

	value, ok := strings.CutPrefix(txt, indexPrefix)
	if !ok {
		return nil, fmt.Errorf("index TXT record does not start with %q: %q", indexPrefix, txt)
	}

	var entries []IndexEntry
	seen := make(map[string]bool)
	for _, pair := range strings.Split(value, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			// Tolerate empty segments such as a trailing comma.
			continue
		}

		name, proto, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("malformed index entry %q: want name:proto", pair)
		}
		name = strings.TrimSpace(name)
		proto = strings.TrimSpace(proto)
		if err := validateIndexField("name", name); err != nil {
			return nil, fmt.Errorf("malformed index entry %q: %w", pair, err)
		}
		if err := validateIndexField("protocol", proto); err != nil {
			return nil, fmt.Errorf("malformed index entry %q: %w", pair, err)
		}
		// DNS name comparison is case-insensitive (RFC 4343), so detect
		// duplicates on the lowercased name while preserving input case.
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("duplicate agent name %q in index", name)
		}
		seen[key] = true

		entries = append(entries, IndexEntry{Name: name, Protocol: proto})
	}
	return entries, nil
}

// FormatIndexTXT formats index entries into the domain index TXT record value
// ("agents=name:proto,...") and returns it split into character-strings of at
// most 255 octets each, as required for a DNS TXT record (RFC 1035).
//
// The value is split at plain byte boundaries every 255 octets. This is
// always valid because TXT character-strings are concatenated verbatim when
// read back, and it avoids edge cases: an agent protocol has no length bound,
// so even a single entry may exceed 255 octets. The output round-trips
// through ParseIndexTXT(chunks...).
func FormatIndexTXT(entries []IndexEntry) ([]string, error) {
	seen := make(map[string]bool)
	pairs := make([]string, 0, len(entries))
	for _, e := range entries {
		if err := validateIndexField("name", e.Name); err != nil {
			return nil, err
		}
		if err := validateIndexField("protocol", e.Protocol); err != nil {
			return nil, err
		}
		// DNS name comparison is case-insensitive (RFC 4343), so detect
		// duplicates on the lowercased name while preserving input case.
		key := strings.ToLower(e.Name)
		if seen[key] {
			return nil, fmt.Errorf("duplicate agent name %q in index", e.Name)
		}
		seen[key] = true

		pairs = append(pairs, e.Name+":"+e.Protocol)
	}

	value := indexPrefix + strings.Join(pairs, ",")
	chunks := make([]string, 0, (len(value)+maxCharStringLen-1)/maxCharStringLen)
	for len(value) > maxCharStringLen {
		chunks = append(chunks, value[:maxCharStringLen])
		value = value[maxCharStringLen:]
	}
	return append(chunks, value), nil
}

// maxCharStringLen is the maximum length of a single character-string in a
// DNS TXT record, in octets (RFC 1035).
const maxCharStringLen = 255

// maxLabelLen is the maximum length of a DNS label in octets (RFC 1035).
const maxLabelLen = 63

// validateIndexField validates one field of an index entry with a whitelist,
// shared by the parse and format paths.
//
// Name must be an LDH DNS label (ASCII letters, digits, and hyphens; 1-63
// octets; no leading or trailing hyphen) because it is prepended to the
// domain as a DNS label. Protocol must be a token matching
// [A-Za-z0-9][A-Za-z0-9+.-]* (e.g. "mcp", "a2a", "https").
//
// These rules are intentionally conservative and may be tuned against the
// reference implementation during interop testing (PR-10).
func validateIndexField(field, value string) error {
	if value == "" {
		return fmt.Errorf("index entry has empty %s", field)
	}
	switch field {
	case "name":
		if len(value) > maxLabelLen {
			return fmt.Errorf("index entry name %q is longer than %d octets", value, maxLabelLen)
		}
		if value[0] == '-' || value[len(value)-1] == '-' {
			return fmt.Errorf("index entry name %q must not start or end with a hyphen", value)
		}
		for i := 0; i < len(value); i++ {
			if !isAlphaNum(value[i]) && value[i] != '-' {
				return fmt.Errorf("index entry name %q is not an LDH DNS label (ASCII letters, digits, hyphens)", value)
			}
		}
	case "protocol":
		if !isAlphaNum(value[0]) {
			return fmt.Errorf("index entry protocol %q must start with an ASCII letter or digit", value)
		}
		for i := 1; i < len(value); i++ {
			c := value[i]
			if !isAlphaNum(c) && c != '+' && c != '.' && c != '-' {
				return fmt.Errorf("index entry protocol %q must match [A-Za-z0-9][A-Za-z0-9+.-]*", value)
			}
		}
	}
	return nil
}

// isAlphaNum reports whether c is an ASCII letter or digit.
func isAlphaNum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

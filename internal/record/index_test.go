package record

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestParseIndexTXT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		txts    []string
		want    []IndexEntry
		wantErr bool
	}{
		{
			name: "single entry",
			txts: []string{"agents=chat:mcp"},
			want: []IndexEntry{{Name: "chat", Protocol: "mcp"}},
		},
		{
			name: "multiple entries keep order",
			txts: []string{"agents=chat:mcp,billing:a2a,support:https"},
			want: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
				{Name: "support", Protocol: "https"},
			},
		},
		{
			name:    "empty string",
			txts:    []string{""},
			wantErr: true,
		},
		{
			name:    "whitespace only",
			txts:    []string{"   "},
			wantErr: true,
		},
		{
			name:    "no arguments",
			txts:    nil,
			wantErr: true,
		},
		{
			name:    "missing agents= prefix",
			txts:    []string{"chat:mcp"},
			wantErr: true,
		},
		{
			name:    "wrong key",
			txts:    []string{"services=chat:mcp"},
			wantErr: true,
		},
		{
			name: "empty value means zero agents",
			txts: []string{"agents="},
			want: nil,
		},
		{
			name: "surrounding and inner whitespace",
			txts: []string{"  agents= chat:mcp , billing:a2a  "},
			want: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
			},
		},
		{
			name: "trailing comma tolerated",
			txts: []string{"agents=chat:mcp,"},
			want: []IndexEntry{{Name: "chat", Protocol: "mcp"}},
		},
		{
			name:    "pair without colon",
			txts:    []string{"agents=chatmcp"},
			wantErr: true,
		},
		{
			name:    "pair with empty name",
			txts:    []string{"agents=:mcp"},
			wantErr: true,
		},
		{
			name:    "pair with empty protocol",
			txts:    []string{"agents=chat:"},
			wantErr: true,
		},
		{
			name:    "pair with extra colon",
			txts:    []string{"agents=chat:mcp:extra"},
			wantErr: true,
		},
		{
			name:    "duplicate agent name",
			txts:    []string{"agents=chat:mcp,chat:a2a"},
			wantErr: true,
		},
		{
			// DNS name comparison is case-insensitive (RFC 4343), so
			// "Chat" and "chat" refer to the same FQDN.
			name:    "duplicate agent name differing only in case",
			txts:    []string{"agents=Chat:mcp,chat:a2a"},
			wantErr: true,
		},
		{
			// The input case of the name must be preserved in the result.
			name: "mixed-case name preserved",
			txts: []string{"agents=Chat:mcp"},
			want: []IndexEntry{{Name: "Chat", Protocol: "mcp"}},
		},
		{
			name:    "whitespace inside name",
			txts:    []string{"agents=cha t:mcp"},
			wantErr: true,
		},
		{
			name:    "whitespace inside protocol",
			txts:    []string{"agents=chat:m cp"},
			wantErr: true,
		},
		{
			name: "multiple TXT character-strings concatenated",
			txts: []string{"agents=chat:mcp,", "billing:a2a"},
			want: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
			},
		},
		{
			name:    "vertical tab inside name",
			txts:    []string{"agents=cha\vt:mcp"},
			wantErr: true,
		},
		{
			name:    "non-breaking space inside name",
			txts:    []string{"agents=cha\u00a0t:mcp"},
			wantErr: true,
		},
		{
			name:    "control character inside name",
			txts:    []string{"agents=cha\x01t:mcp"},
			wantErr: true,
		},
		{
			name:    "dot inside name",
			txts:    []string{"agents=chat.example:mcp"},
			wantErr: true,
		},
		{
			name:    "name longer than 63 octets",
			txts:    []string{"agents=" + strings.Repeat("a", 64) + ":mcp"},
			wantErr: true,
		},
		{
			name:    "name with leading hyphen",
			txts:    []string{"agents=-chat:mcp"},
			wantErr: true,
		},
		{
			name:    "name with trailing hyphen",
			txts:    []string{"agents=chat-:mcp"},
			wantErr: true,
		},
		{
			name:    "non-ASCII name",
			txts:    []string{"agents=chät:mcp"},
			wantErr: true,
		},
		{
			name:    "protocol with invalid character",
			txts:    []string{"agents=chat:m_cp"},
			wantErr: true,
		},
		{
			name:    "protocol with leading plus",
			txts:    []string{"agents=chat:+mcp"},
			wantErr: true,
		},
		{
			name: "name at 63 octets with inner hyphen",
			txts: []string{"agents=" + strings.Repeat("a", 30) + "-" + strings.Repeat("b", 32) + ":mcp"},
			want: []IndexEntry{{
				Name:     strings.Repeat("a", 30) + "-" + strings.Repeat("b", 32),
				Protocol: "mcp",
			}},
		},
		{
			name: "protocol with plus dot and hyphen",
			txts: []string{"agents=chat:coap+tcp.v1-x"},
			want: []IndexEntry{{Name: "chat", Protocol: "coap+tcp.v1-x"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseIndexTXT(tt.txts...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseIndexTXT(%q) = %v, want error", tt.txts, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIndexTXT(%q) returned unexpected error: %v", tt.txts, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ParseIndexTXT(%q) = %v, want %v", tt.txts, got, tt.want)
			}
		})
	}
}

func TestFormatIndexTXT(t *testing.T) {
	t.Parallel()

	// A single entry whose formatted form exceeds 255 octets: protocols have
	// no length bound, so splitting must work at arbitrary byte boundaries.
	longProto := strings.Repeat("p", 300)
	longSingle := "agents=chat:" + longProto

	tests := []struct {
		name    string
		entries []IndexEntry
		want    []string
		wantErr bool
	}{
		{
			name: "multiple entries",
			entries: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
			},
			want: []string{"agents=chat:mcp,billing:a2a"},
		},
		{
			name:    "no entries",
			entries: nil,
			want:    []string{"agents="},
		},
		{
			name:    "single entry longer than 255 octets splits at byte boundary",
			entries: []IndexEntry{{Name: "chat", Protocol: longProto}},
			want:    []string{longSingle[:255], longSingle[255:]},
		},
		{
			name:    "empty name",
			entries: []IndexEntry{{Name: "", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "empty protocol",
			entries: []IndexEntry{{Name: "chat", Protocol: ""}},
			wantErr: true,
		},
		{
			name:    "name containing separator",
			entries: []IndexEntry{{Name: "chat,billing", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "protocol containing colon",
			entries: []IndexEntry{{Name: "chat", Protocol: "mcp:1"}},
			wantErr: true,
		},
		{
			name:    "name containing whitespace",
			entries: []IndexEntry{{Name: "chat bot", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name: "duplicate names",
			entries: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "chat", Protocol: "a2a"},
			},
			wantErr: true,
		},
		{
			// DNS name comparison is case-insensitive (RFC 4343), so
			// "Chat" and "chat" refer to the same FQDN.
			name: "duplicate names differing only in case",
			entries: []IndexEntry{
				{Name: "Chat", Protocol: "mcp"},
				{Name: "chat", Protocol: "a2a"},
			},
			wantErr: true,
		},
		{
			// Regression for the round-trip break: "a\v" used to be
			// formatted verbatim but re-parsed as "a".
			name:    "name with vertical tab",
			entries: []IndexEntry{{Name: "a\v", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name with non-breaking space",
			entries: []IndexEntry{{Name: "cha\u00a0t", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name with control character",
			entries: []IndexEntry{{Name: "cha\x01t", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name with dot",
			entries: []IndexEntry{{Name: "chat.example", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name longer than 63 octets",
			entries: []IndexEntry{{Name: strings.Repeat("a", 64), Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name with leading hyphen",
			entries: []IndexEntry{{Name: "-chat", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "name with trailing hyphen",
			entries: []IndexEntry{{Name: "chat-", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "non-ASCII name",
			entries: []IndexEntry{{Name: "chät", Protocol: "mcp"}},
			wantErr: true,
		},
		{
			name:    "protocol with invalid character",
			entries: []IndexEntry{{Name: "chat", Protocol: "m_cp"}},
			wantErr: true,
		},
		{
			name:    "protocol with leading hyphen",
			entries: []IndexEntry{{Name: "chat", Protocol: "-mcp"}},
			wantErr: true,
		},
		{
			name:    "name at 63 octets",
			entries: []IndexEntry{{Name: strings.Repeat("a", 63), Protocol: "mcp"}},
			want:    []string{"agents=" + strings.Repeat("a", 63) + ":mcp"},
		},
		{
			name:    "protocol with plus dot and hyphen",
			entries: []IndexEntry{{Name: "chat", Protocol: "coap+tcp.v1-x"}},
			want:    []string{"agents=chat:coap+tcp.v1-x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := FormatIndexTXT(tt.entries)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("FormatIndexTXT(%v) = %q, want error", tt.entries, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FormatIndexTXT(%v) returned unexpected error: %v", tt.entries, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatIndexTXT(%v) = %q, want %q", tt.entries, got, tt.want)
			}
		})
	}
}

// TestFormatIndexTXTSplitsLongValue checks that a formatted value longer than
// 255 octets is split into multiple character-strings, each at most 255
// octets, that concatenate back to the full value and round-trip through
// ParseIndexTXT.
func TestFormatIndexTXTSplitsLongValue(t *testing.T) {
	t.Parallel()

	// Build enough entries that the joined value clearly exceeds 255 octets.
	var entries []IndexEntry
	pairs := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("agent-%02d-%s", i, strings.Repeat("x", 30))
		entries = append(entries, IndexEntry{Name: name, Protocol: "mcp"})
		pairs = append(pairs, name+":mcp")
	}
	full := "agents=" + strings.Join(pairs, ",")
	if len(full) <= 255 {
		t.Fatalf("test setup: formatted value is %d octets, want > 255", len(full))
	}

	chunks, err := FormatIndexTXT(entries)
	if err != nil {
		t.Fatalf("FormatIndexTXT(%v) returned unexpected error: %v", entries, err)
	}
	if len(chunks) < 2 {
		t.Fatalf("FormatIndexTXT returned %d chunk(s) for a %d-octet value, want >= 2", len(chunks), len(full))
	}
	for i, c := range chunks {
		if len(c) == 0 {
			t.Errorf("chunk %d is empty", i)
		}
		if len(c) > 255 {
			t.Errorf("chunk %d is %d octets, want <= 255", i, len(c))
		}
	}
	if got := strings.Join(chunks, ""); got != full {
		t.Errorf("concatenated chunks = %q, want %q", got, full)
	}

	reparsed, err := ParseIndexTXT(chunks...)
	if err != nil {
		t.Fatalf("ParseIndexTXT(%q) returned unexpected error: %v", chunks, err)
	}
	if !slices.Equal(reparsed, entries) {
		t.Errorf("round trip mismatch: got %v, want %v", reparsed, entries)
	}
}

func TestIndexTXTRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []IndexEntry
	}{
		{
			name: "typical entries",
			entries: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
				{Name: "support", Protocol: "https"},
			},
		},
		{
			name:    "no entries",
			entries: nil,
		},
		{
			name: "entries formatting to more than 255 octets",
			entries: []IndexEntry{
				{Name: strings.Repeat("a", 63), Protocol: "mcp"},
				{Name: strings.Repeat("b", 63), Protocol: "a2a"},
				{Name: strings.Repeat("c", 63), Protocol: "https"},
				{Name: strings.Repeat("d", 63), Protocol: "mcp"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chunks, err := FormatIndexTXT(tt.entries)
			if err != nil {
				t.Fatalf("FormatIndexTXT(%v) returned unexpected error: %v", tt.entries, err)
			}
			got, err := ParseIndexTXT(chunks...)
			if err != nil {
				t.Fatalf("ParseIndexTXT(%q) returned unexpected error: %v", chunks, err)
			}
			if !slices.Equal(got, tt.entries) {
				t.Errorf("round trip mismatch: got %v, want %v", got, tt.entries)
			}
		})
	}
}

// FuzzParseIndexTXT checks that ParseIndexTXT never panics and that any
// successfully parsed input round-trips: format the result, parse it again,
// and require the same entries.
func FuzzParseIndexTXT(f *testing.F) {
	f.Add("agents=chat:mcp,billing:a2a")
	f.Add("agents=")
	f.Add("agents=chat:mcp,")
	f.Add("  agents= chat:mcp , billing:a2a  ")
	f.Add("agents=:bad")
	f.Add("not-an-index")
	f.Add("")

	f.Fuzz(func(t *testing.T, txt string) {
		entries, err := ParseIndexTXT(txt)
		if err != nil {
			return
		}

		chunks, err := FormatIndexTXT(entries)
		if err != nil {
			t.Fatalf("FormatIndexTXT(%v) failed on entries parsed from %q: %v", entries, txt, err)
		}
		for i, c := range chunks {
			if len(c) > 255 {
				t.Errorf("chunk %d of formatted output of %q is %d octets, want <= 255", i, txt, len(c))
			}
		}
		reparsed, err := ParseIndexTXT(chunks...)
		if err != nil {
			t.Fatalf("ParseIndexTXT(%q) failed on formatted output of %q: %v", chunks, txt, err)
		}
		if !slices.Equal(reparsed, entries) {
			t.Errorf("round trip mismatch for %q: got %v, want %v", txt, reparsed, entries)
		}
	})
}

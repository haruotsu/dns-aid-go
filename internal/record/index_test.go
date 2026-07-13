package record

import (
	"slices"
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

	tests := []struct {
		name    string
		entries []IndexEntry
		want    string
		wantErr bool
	}{
		{
			name: "multiple entries",
			entries: []IndexEntry{
				{Name: "chat", Protocol: "mcp"},
				{Name: "billing", Protocol: "a2a"},
			},
			want: "agents=chat:mcp,billing:a2a",
		},
		{
			name:    "no entries",
			entries: nil,
			want:    "agents=",
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
			if got != tt.want {
				t.Errorf("FormatIndexTXT(%v) = %q, want %q", tt.entries, got, tt.want)
			}
		})
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			txt, err := FormatIndexTXT(tt.entries)
			if err != nil {
				t.Fatalf("FormatIndexTXT(%v) returned unexpected error: %v", tt.entries, err)
			}
			got, err := ParseIndexTXT(txt)
			if err != nil {
				t.Fatalf("ParseIndexTXT(%q) returned unexpected error: %v", txt, err)
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

		formatted, err := FormatIndexTXT(entries)
		if err != nil {
			t.Fatalf("FormatIndexTXT(%v) failed on entries parsed from %q: %v", entries, txt, err)
		}
		reparsed, err := ParseIndexTXT(formatted)
		if err != nil {
			t.Fatalf("ParseIndexTXT(%q) failed on formatted output of %q: %v", formatted, txt, err)
		}
		if !slices.Equal(reparsed, entries) {
			t.Errorf("round trip mismatch for %q: got %v, want %v", txt, reparsed, entries)
		}
	})
}

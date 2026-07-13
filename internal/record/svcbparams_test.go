package record

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// local is a shorthand for building a private-use SVCB parameter.
func local(key dns.SVCBKey, value string) *dns.SVCBLocal {
	return &dns.SVCBLocal{KeyCode: key, Data: []byte(value)}
}

// equalSVCBParams compares two SVCBParams treating nil and empty Unknown data
// as equal.
func equalSVCBParams(a, b SVCBParams) bool {
	if a.Cap != b.Cap || a.CapSHA256 != b.CapSHA256 || a.BAP != b.BAP ||
		a.Policy != b.Policy || a.Realm != b.Realm || a.Sig != b.Sig {
		return false
	}
	if len(a.Unknown) != len(b.Unknown) {
		return false
	}
	for i := range a.Unknown {
		if a.Unknown[i].Key != b.Unknown[i].Key || !bytes.Equal(a.Unknown[i].Data, b.Unknown[i].Data) {
			return false
		}
	}
	return true
}

func TestParseSVCBParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kvs     []dns.SVCBKeyValue
		want    SVCBParams
		wantErr bool
	}{
		{
			name: "all six draft keys map to fields",
			kvs: []dns.SVCBKeyValue{
				local(65400, "https://mcp.example.com/.well-known/agent-cap.json"),
				local(65401, "dGVzdGhhc2g"),
				local(65402, "mcp/1,a2a/1"),
				local(65403, "https://example.com/agent-policy"),
				local(65404, "production"),
				local(65405, "c2lnbmF0dXJl"),
			},
			want: SVCBParams{
				Cap:       "https://mcp.example.com/.well-known/agent-cap.json",
				CapSHA256: "dGVzdGhhc2g",
				BAP:       "mcp/1,a2a/1",
				Policy:    "https://example.com/agent-policy",
				Realm:     "production",
				Sig:       "c2lnbmF0dXJl",
			},
		},
		{
			name: "empty input",
			kvs:  nil,
			want: SVCBParams{},
		},
		{
			name: "subset of keys",
			kvs: []dns.SVCBKeyValue{
				local(65400, "https://example.com/cap.json"),
				local(65404, "staging"),
			},
			want: SVCBParams{
				Cap:   "https://example.com/cap.json",
				Realm: "staging",
			},
		},
		{
			name: "unknown private-use key is preserved",
			kvs: []dns.SVCBKeyValue{
				local(65400, "https://example.com/cap.json"),
				local(65406, "future-extension"),
			},
			want: SVCBParams{
				Cap: "https://example.com/cap.json",
				Unknown: []SVCBUnknownParam{
					{Key: 65406, Data: []byte("future-extension")},
				},
			},
		},
		{
			name: "multiple unknown keys keep order",
			kvs: []dns.SVCBKeyValue{
				local(65409, "b"),
				local(65406, "a"),
			},
			want: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 65409, Data: []byte("b")},
					{Key: 65406, Data: []byte("a")},
				},
			},
		},
		{
			name: "unknown key at private range bounds",
			kvs: []dns.SVCBKeyValue{
				local(65280, "lower"),
				local(65534, "upper"),
			},
			want: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 65280, Data: []byte("lower")},
					{Key: 65534, Data: []byte("upper")},
				},
			},
		},
		{
			name: "standard parameters are ignored",
			kvs: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"mcp"}},
				&dns.SVCBPort{Port: 443},
				local(65400, "https://example.com/cap.json"),
			},
			want: SVCBParams{Cap: "https://example.com/cap.json"},
		},
		{
			name: "duplicate draft key",
			kvs: []dns.SVCBKeyValue{
				local(65400, "https://example.com/a.json"),
				local(65400, "https://example.com/b.json"),
			},
			wantErr: true,
		},
		{
			name: "duplicate unknown key",
			kvs: []dns.SVCBKeyValue{
				local(65406, "a"),
				local(65406, "b"),
			},
			wantErr: true,
		},
		{
			// A named field cannot represent "present but empty", so an
			// empty value for a draft key is treated as absent.
			name: "empty value for a draft key is treated as absent",
			kvs: []dns.SVCBKeyValue{
				local(65404, ""),
			},
			want: SVCBParams{},
		},
		{
			// Unknown keys must be preserved verbatim, including an empty
			// value: presence is representable in the Unknown slice.
			name: "unknown key with empty value is preserved",
			kvs: []dns.SVCBKeyValue{
				local(65406, ""),
			},
			want: SVCBParams{
				Unknown: []SVCBUnknownParam{{Key: 65406, Data: nil}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSVCBParams(tt.kvs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSVCBParams(%v) = %+v, want error", tt.kvs, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSVCBParams(%v) returned unexpected error: %v", tt.kvs, err)
			}
			if !equalSVCBParams(got, tt.want) {
				t.Errorf("ParseSVCBParams(%v) = %+v, want %+v", tt.kvs, got, tt.want)
			}
		})
	}
}

func TestFormatSVCBParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		params  SVCBParams
		want    []dns.SVCBKeyValue
		wantErr bool
	}{
		{
			name: "all six fields in ascending key order",
			params: SVCBParams{
				Cap:       "https://mcp.example.com/.well-known/agent-cap.json",
				CapSHA256: "dGVzdGhhc2g",
				BAP:       "mcp/1,a2a/1",
				Policy:    "https://example.com/agent-policy",
				Realm:     "production",
				Sig:       "c2lnbmF0dXJl",
			},
			want: []dns.SVCBKeyValue{
				local(65400, "https://mcp.example.com/.well-known/agent-cap.json"),
				local(65401, "dGVzdGhhc2g"),
				local(65402, "mcp/1,a2a/1"),
				local(65403, "https://example.com/agent-policy"),
				local(65404, "production"),
				local(65405, "c2lnbmF0dXJl"),
			},
		},
		{
			name:   "zero value formats to nothing",
			params: SVCBParams{},
			want:   nil,
		},
		{
			name:   "empty fields are omitted",
			params: SVCBParams{Realm: "production"},
			want:   []dns.SVCBKeyValue{local(65404, "production")},
		},
		{
			name: "unknown keys follow known keys in given order",
			params: SVCBParams{
				Realm: "production",
				Unknown: []SVCBUnknownParam{
					{Key: 65409, Data: []byte("b")},
					{Key: 65406, Data: []byte("a")},
				},
			},
			want: []dns.SVCBKeyValue{
				local(65404, "production"),
				local(65409, "b"),
				local(65406, "a"),
			},
		},
		{
			name: "unknown key colliding with a draft key",
			params: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 65400, Data: []byte("collides-with-cap")},
				},
			},
			wantErr: true,
		},
		{
			name: "unknown key below the private-use range",
			params: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 3, Data: []byte("port-is-not-private")},
				},
			},
			wantErr: true,
		},
		{
			name: "unknown key above the private-use range",
			params: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 65535, Data: []byte("reserved")},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate unknown keys",
			params: SVCBParams{
				Unknown: []SVCBUnknownParam{
					{Key: 65406, Data: []byte("a")},
					{Key: 65406, Data: []byte("b")},
				},
			},
			wantErr: true,
		},
		{
			name:    "value longer than 65535 octets",
			params:  SVCBParams{Realm: strings.Repeat("r", 65536)},
			wantErr: true,
		},
		{
			name:    "value of exactly 65535 octets",
			params:  SVCBParams{Realm: strings.Repeat("r", 65535)},
			want:    []dns.SVCBKeyValue{local(65404, strings.Repeat("r", 65535))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := FormatSVCBParams(tt.params)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("FormatSVCBParams(%+v) = %v, want error", tt.params, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FormatSVCBParams(%+v) returned unexpected error: %v", tt.params, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("FormatSVCBParams(%+v) = %v, want %v", tt.params, got, tt.want)
			}
			for i := range got {
				w := tt.want[i].(*dns.SVCBLocal)
				g, ok := got[i].(*dns.SVCBLocal)
				if !ok {
					t.Fatalf("FormatSVCBParams(%+v)[%d] = %T, want *dns.SVCBLocal", tt.params, i, got[i])
				}
				if g.KeyCode != w.KeyCode || !bytes.Equal(g.Data, w.Data) {
					t.Errorf("FormatSVCBParams(%+v)[%d] = key%d %q, want key%d %q",
						tt.params, i, g.KeyCode, g.Data, w.KeyCode, w.Data)
				}
			}
		})
	}
}

func TestSVCBParamsRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params SVCBParams
	}{
		{
			name: "all fields",
			params: SVCBParams{
				Cap:       "https://mcp.example.com/.well-known/agent-cap.json",
				CapSHA256: "dGVzdGhhc2g",
				BAP:       "mcp/1,a2a/1",
				Policy:    "https://example.com/agent-policy",
				Realm:     "production",
				Sig:       "c2lnbmF0dXJl",
			},
		},
		{
			name:   "zero value",
			params: SVCBParams{},
		},
		{
			name: "fields and unknown keys",
			params: SVCBParams{
				Cap: "https://example.com/cap.json",
				Unknown: []SVCBUnknownParam{
					{Key: 65409, Data: []byte("b")},
					{Key: 65406, Data: []byte{0x00, 0xff, 0x7f}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kvs, err := FormatSVCBParams(tt.params)
			if err != nil {
				t.Fatalf("FormatSVCBParams(%+v) returned unexpected error: %v", tt.params, err)
			}
			got, err := ParseSVCBParams(kvs)
			if err != nil {
				t.Fatalf("ParseSVCBParams(%v) returned unexpected error: %v", kvs, err)
			}
			if !equalSVCBParams(got, tt.params) {
				t.Errorf("round trip mismatch: got %+v, want %+v", got, tt.params)
			}
		})
	}
}

// TestParseSVCBParamsFromZoneRecord checks the integration with miekg/dns zone
// parsing: a record written in the draft's wire format (OSS-03 §3.2) must
// decode to the same logical values.
func TestParseSVCBParamsFromZoneRecord(t *testing.T) {
	t.Parallel()

	rr, err := dns.NewRR(`booking.example.com. 3600 IN SVCB 1 mcp.example.com. alpn="mcp" port=443 ` +
		`key65400="https://mcp.example.com/.well-known/agent-cap.json" ` +
		`key65401="dGVzdGhhc2g" key65402="mcp/1,a2a/1" ` +
		`key65403="https://example.com/agent-policy" key65404="production"`)
	if err != nil {
		t.Fatalf("dns.NewRR returned unexpected error: %v", err)
	}
	svcb, ok := rr.(*dns.SVCB)
	if !ok {
		t.Fatalf("dns.NewRR returned %T, want *dns.SVCB", rr)
	}

	got, err := ParseSVCBParams(svcb.Value)
	if err != nil {
		t.Fatalf("ParseSVCBParams(%v) returned unexpected error: %v", svcb.Value, err)
	}
	want := SVCBParams{
		Cap:       "https://mcp.example.com/.well-known/agent-cap.json",
		CapSHA256: "dGVzdGhhc2g",
		BAP:       "mcp/1,a2a/1",
		Policy:    "https://example.com/agent-policy",
		Realm:     "production",
	}
	if !equalSVCBParams(got, want) {
		t.Errorf("ParseSVCBParams from zone record = %+v, want %+v", got, want)
	}
}

func TestSVCBParamName(t *testing.T) {
	t.Parallel()

	// The mapping must correspond 1:1 to the OSS-03 §3.3 table.
	known := map[dns.SVCBKey]string{
		65400: "cap",
		65401: "cap-sha256",
		65402: "bap",
		65403: "policy",
		65404: "realm",
		65405: "sig",
	}
	for key, name := range known {
		got, ok := SVCBParamName(key)
		if !ok || got != name {
			t.Errorf("SVCBParamName(%d) = %q, %v, want %q, true", key, got, ok, name)
		}
	}

	for _, key := range []dns.SVCBKey{0, 3, 65280, 65399, 65406, 65534, 65535} {
		if name, ok := SVCBParamName(key); ok {
			t.Errorf("SVCBParamName(%d) = %q, true, want ok=false", key, name)
		}
	}
}

func TestSVCBParamKey(t *testing.T) {
	t.Parallel()

	known := map[string]dns.SVCBKey{
		"cap":        65400,
		"cap-sha256": 65401,
		"bap":        65402,
		"policy":     65403,
		"realm":      65404,
		"sig":        65405,
	}
	for name, key := range known {
		got, ok := SVCBParamKey(name)
		if !ok || got != key {
			t.Errorf("SVCBParamKey(%q) = %d, %v, want %d, true", name, got, ok, key)
		}
	}

	for _, name := range []string{"", "alpn", "port", "CAP", "capability", "cap-sha512"} {
		if key, ok := SVCBParamKey(name); ok {
			t.Errorf("SVCBParamKey(%q) = %d, true, want ok=false", name, key)
		}
	}
}

// FuzzSVCBParamsRoundTrip checks that any SVCBParams accepted by
// FormatSVCBParams survives a format→parse round trip unchanged.
func FuzzSVCBParamsRoundTrip(f *testing.F) {
	f.Add("https://example.com/cap.json", "dGVzdGhhc2g", "mcp/1", "https://example.com/policy", "production", "c2ln", uint16(65406), []byte("x"))
	f.Add("", "", "", "", "", "", uint16(65280), []byte{})
	f.Add("", "", "", "", "", "", uint16(0), []byte("not-private"))
	f.Add("", "", "", "", "", "", uint16(65400), []byte("collision"))

	f.Fuzz(func(t *testing.T, cap, capSHA256, bap, policy, realm, sig string, ukey uint16, udata []byte) {
		params := SVCBParams{
			Cap:       cap,
			CapSHA256: capSHA256,
			BAP:       bap,
			Policy:    policy,
			Realm:     realm,
			Sig:       sig,
			Unknown:   []SVCBUnknownParam{{Key: dns.SVCBKey(ukey), Data: udata}},
		}

		kvs, err := FormatSVCBParams(params)
		if err != nil {
			// Invalid input (e.g. out-of-range unknown key) is allowed to
			// fail; the round-trip property only applies to accepted input.
			return
		}
		got, err := ParseSVCBParams(kvs)
		if err != nil {
			t.Fatalf("ParseSVCBParams(%v) failed on formatted output of %+v: %v", kvs, params, err)
		}

		if !equalSVCBParams(got, params) {
			t.Errorf("round trip mismatch: got %+v, want %+v", got, params)
		}
	})
}

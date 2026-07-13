package record

import (
	"fmt"

	"github.com/miekg/dns"
)

// SVCB private-use key assignments defined by
// draft-mozleywilliams-dnsop-dnsaid (OSS-03 §3.3). This table is the single
// place where key codes are assigned; a draft revision that renumbers the
// keys must only touch this block (N-6).
const (
	KeyCap       dns.SVCBKey = 65400 // cap: capability document URI
	KeyCapSHA256 dns.SVCBKey = 65401 // cap-sha256: base64url digest of the cap document
	KeyBAP       dns.SVCBKey = 65402 // bap: baseline agent protocols ("proto/ver,...")
	KeyPolicy    dns.SVCBKey = 65403 // policy: policy document URI
	KeyRealm     dns.SVCBKey = 65404 // realm: deployment realm label
	KeySig       dns.SVCBKey = 65405 // sig: record signature
)

// svcbPrivateLower and svcbPrivateUpper bound the SVCB "Private Use" key
// range (RFC 9460 §14.3.2). Key 65535 is reserved.
const (
	svcbPrivateLower dns.SVCBKey = 65280
	svcbPrivateUpper dns.SVCBKey = 65534
)

// maxSVCBValueLen is the maximum length of a single SvcParamValue in octets:
// its wire format carries a 16-bit length prefix (RFC 9460 §2.2).
const maxSVCBValueLen = 65535

// SVCBParams holds the draft's custom SVCB parameters of one agent record in
// logical form. A named field is absent when empty: the wire form cannot be
// usefully distinguished from an empty value for these parameters.
//
// Unknown preserves private-use parameters this implementation does not know
// (future draft extensions) so that read-modify-write cycles do not drop
// them.
type SVCBParams struct {
	Cap       string // key65400
	CapSHA256 string // key65401
	BAP       string // key65402
	Policy    string // key65403
	Realm     string // key65404
	Sig       string // key65405

	Unknown []SVCBUnknownParam
}

// SVCBUnknownParam is a private-use SVCB parameter outside the draft's key
// assignments, preserved verbatim.
type SVCBUnknownParam struct {
	Key  dns.SVCBKey
	Data []byte
}

// paramFields binds each draft key to its logical name and SVCBParams field.
// The order of this table is the canonical output order of FormatSVCBParams.
var paramFields = []struct {
	key   dns.SVCBKey
	name  string
	field func(*SVCBParams) *string
}{
	{KeyCap, "cap", func(p *SVCBParams) *string { return &p.Cap }},
	{KeyCapSHA256, "cap-sha256", func(p *SVCBParams) *string { return &p.CapSHA256 }},
	{KeyBAP, "bap", func(p *SVCBParams) *string { return &p.BAP }},
	{KeyPolicy, "policy", func(p *SVCBParams) *string { return &p.Policy }},
	{KeyRealm, "realm", func(p *SVCBParams) *string { return &p.Realm }},
	{KeySig, "sig", func(p *SVCBParams) *string { return &p.Sig }},
}

// SVCBParamName returns the logical name ("cap", "cap-sha256", ...) of a
// draft key. It reports false for any key outside the draft's assignments.
func SVCBParamName(key dns.SVCBKey) (string, bool) {
	for _, f := range paramFields {
		if f.key == key {
			return f.name, true
		}
	}
	return "", false
}

// SVCBParamKey returns the draft key for a logical name ("cap",
// "cap-sha256", ...). It reports false for any other name.
func SVCBParamKey(name string) (dns.SVCBKey, bool) {
	for _, f := range paramFields {
		if f.name == name {
			return f.key, true
		}
	}
	return 0, false
}

// ParseSVCBParams extracts the draft's custom parameters from the
// SvcParams of one SVCB record. Standard (non-private-use) parameters such
// as alpn and port are ignored; they are handled by the caller. Unknown
// private-use parameters are preserved in SVCBParams.Unknown in input order.
//
// A duplicate private-use key is an error: an SVCB record must not carry the
// same SvcParamKey twice (RFC 9460 §2.2).
func ParseSVCBParams(kvs []dns.SVCBKeyValue) (SVCBParams, error) {
	var params SVCBParams
	seen := make(map[dns.SVCBKey]bool)
	for _, kv := range kvs {
		key := kv.Key()
		if key < svcbPrivateLower || key > svcbPrivateUpper {
			continue
		}

		lv, ok := kv.(*dns.SVCBLocal)
		if !ok {
			return SVCBParams{}, fmt.Errorf("private-use SVCB parameter %s has unexpected type %T", key, kv)
		}
		if seen[key] {
			return SVCBParams{}, fmt.Errorf("duplicate SVCB parameter %s", key)
		}
		seen[key] = true

		if field, ok := draftField(&params, key); ok {
			*field = string(lv.Data)
			continue
		}
		data := append([]byte(nil), lv.Data...)
		params.Unknown = append(params.Unknown, SVCBUnknownParam{Key: key, Data: data})
	}
	return params, nil
}

// FormatSVCBParams encodes the parameters into SvcParams for one SVCB
// record: draft keys first in ascending key order, then Unknown in its own
// order. Empty named fields are omitted. The output round-trips through
// ParseSVCBParams.
func FormatSVCBParams(params SVCBParams) ([]dns.SVCBKeyValue, error) {
	var kvs []dns.SVCBKeyValue
	for _, f := range paramFields {
		value := *f.field(&params)
		if value == "" {
			continue
		}
		if len(value) > maxSVCBValueLen {
			return nil, fmt.Errorf("SVCB parameter %s value is %d octets, max %d", f.name, len(value), maxSVCBValueLen)
		}
		kvs = append(kvs, &dns.SVCBLocal{KeyCode: f.key, Data: []byte(value)})
	}

	seen := make(map[dns.SVCBKey]bool)
	for _, u := range params.Unknown {
		if u.Key < svcbPrivateLower || u.Key > svcbPrivateUpper {
			return nil, fmt.Errorf("unknown SVCB parameter key%d is outside the private-use range [%d, %d]",
				uint16(u.Key), uint16(svcbPrivateLower), uint16(svcbPrivateUpper))
		}
		if name, ok := SVCBParamName(u.Key); ok {
			return nil, fmt.Errorf("unknown SVCB parameter %s collides with draft key %q; set the named field instead", u.Key, name)
		}
		if seen[u.Key] {
			return nil, fmt.Errorf("duplicate unknown SVCB parameter %s", u.Key)
		}
		seen[u.Key] = true

		if len(u.Data) > maxSVCBValueLen {
			return nil, fmt.Errorf("SVCB parameter %s value is %d octets, max %d", u.Key, len(u.Data), maxSVCBValueLen)
		}
		data := append([]byte(nil), u.Data...)
		kvs = append(kvs, &dns.SVCBLocal{KeyCode: u.Key, Data: data})
	}
	return kvs, nil
}

// draftField returns a pointer to the SVCBParams field assigned to key, if
// key is one of the draft's assignments.
func draftField(params *SVCBParams, key dns.SVCBKey) (*string, bool) {
	for _, f := range paramFields {
		if f.key == key {
			return f.field(params), true
		}
	}
	return nil, false
}

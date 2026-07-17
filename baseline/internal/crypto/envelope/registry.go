package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/kvlt/key-vault/internal/crypto/aead"
)

// FormatID identifies a versioned ciphertext container. It is selected by
// policy, never inferred from an unauthenticated request field alone.
type FormatID string

const (
	FormatKVLTBinaryV1       FormatID = "kvlt-binary-v1"
	FormatJSONV1             FormatID = "json-v1"
	FormatConfigurableJSONV1 FormatID = "configurable-json-v1"
)

// FormatDescription describes a registered format for listing/display.
type FormatDescription struct {
	ID          FormatID `json:"format_id"`
	Description string   `json:"description"`
	MatchRule   string   `json:"match_rule"`
}

type Codec interface {
	ID() FormatID
	Match([]byte) bool
	Encode(*Envelope) ([]byte, error)
	Decode([]byte) (*Envelope, error)
}

type Adapter interface {
	Codec
	EncodeWithProfile(*Envelope, *FormatProfile, RenderContext) ([]byte, error)
	DecodeWithProfile([]byte, *FormatProfile) (*Envelope, ExtensionBag, error)
}

type Registry struct {
	codecs map[FormatID]Codec
	order  []FormatID // preserves listing order
	descs  map[FormatID]string
}

func NewRegistry(codecs ...Codec) *Registry {
	r := &Registry{codecs: make(map[FormatID]Codec), descs: make(map[FormatID]string)}
	for _, c := range codecs {
		r.codecs[c.ID()] = c
		r.order = append(r.order, c.ID())
	}
	return r
}

// DefaultRegistry returns a registry with all built-in codecs registered.
func DefaultRegistry() *Registry {
	return NewRegistry(
		binaryCodec{},
		jsonCodec{},
		configurableJSONCodec{},
	)
}

// SetDescription attaches a human-readable description to a format ID.
func (r *Registry) SetDescription(id FormatID, desc string) {
	r.descs[id] = desc
}

// ListFormats returns descriptions of all registered formats.
func (r *Registry) ListFormats() []FormatDescription {
	defaults := map[FormatID]string{
		FormatKVLTBinaryV1:       "Native binary format with KVLT magic header, most efficient for internal systems",
		FormatJSONV1:             "JSON object with base64-encoded fields, for REST API integration and debugging",
		FormatConfigurableJSONV1: "Profile-driven JSON adapter for tenant and partner envelope formats",
	}
	out := make([]FormatDescription, 0, len(r.order))
	for _, id := range r.order {
		desc := r.descs[id]
		if desc == "" {
			desc = defaults[id]
		}
		matchRule := "unknown"
		if c, ok := r.codecs[id]; ok {
			switch id {
			case FormatKVLTBinaryV1:
				matchRule = "first 4 bytes == 'KVLT'"
			case FormatJSONV1:
				matchRule = "first non-whitespace byte == '{'"
			case FormatConfigurableJSONV1:
				matchRule = "profile-driven JSON object"
			default:
				_ = c
			}
		}
		out = append(out, FormatDescription{ID: id, Description: desc, MatchRule: matchRule})
	}
	return out
}

func (r *Registry) Codec(id FormatID) (Codec, error) {
	c, ok := r.codecs[id]
	if !ok {
		return nil, fmt.Errorf("envelope: unsupported format %q", id)
	}
	return c, nil
}
func (r *Registry) Detect(b []byte) (Codec, error) {
	for _, id := range r.order {
		c := r.codecs[id]
		if c.Match(b) {
			return c, nil
		}
	}
	return nil, ErrInvalid
}
func (r *Registry) Parse(id FormatID, b []byte) (*Envelope, error) {
	c, err := r.Codec(id)
	if err != nil {
		return nil, err
	}
	return c.Decode(b)
}

// Encode serializes the already-authenticated normalized envelope.
func (r *Registry) Encode(id FormatID, env *Envelope) ([]byte, error) {
	c, err := r.Codec(id)
	if err != nil {
		return nil, err
	}
	return c.Encode(env)
}
func (r *Registry) EncodeWithProfile(profile *FormatProfile, env *Envelope, ctx RenderContext) ([]byte, error) {
	if profile == nil {
		profile = BuiltinProfile(FormatKVLTBinaryV1)
	}
	adapterID := profile.Adapter
	if adapterID == "" {
		adapterID = profile.FormatID
	}
	c, err := r.Codec(adapterID)
	if err != nil {
		return nil, err
	}
	if a, ok := c.(Adapter); ok {
		return a.EncodeWithProfile(env, profile, ctx)
	}
	return c.Encode(env)
}

func (r *Registry) ParseWithProfile(profile *FormatProfile, b []byte) (*Envelope, ExtensionBag, error) {
	if profile == nil {
		return nil, nil, ErrInvalid
	}
	adapterID := profile.Adapter
	if adapterID == "" {
		adapterID = profile.FormatID
	}
	c, err := r.Codec(adapterID)
	if err != nil {
		return nil, nil, err
	}
	if a, ok := c.(Adapter); ok {
		return a.DecodeWithProfile(b, profile)
	}
	env, err := c.Decode(b)
	return env, nil, err
}

func (r *Registry) Open(id FormatID, b, key, callerAAD []byte) (*Envelope, []byte, error) {
	env, err := r.Parse(id, b)
	if err != nil {
		return nil, nil, err
	}
	raw, err := env.Encode()
	if err != nil {
		return nil, nil, err
	}
	return Open(raw, key, callerAAD)
}

func (r *Registry) OpenWithProfile(profile *FormatProfile, b, key, callerAAD []byte) (*Envelope, []byte, error) {
	env, _, err := r.ParseWithProfile(profile, b)
	if err != nil {
		return nil, nil, err
	}
	raw, err := env.Encode()
	if err != nil {
		return nil, nil, err
	}
	return Open(raw, key, callerAAD)
}

type binaryCodec struct{}

func (binaryCodec) ID() FormatID                       { return FormatKVLTBinaryV1 }
func (binaryCodec) Match(b []byte) bool                { return len(b) >= 4 && bytes.Equal(b[:4], Magic[:]) }
func (binaryCodec) Encode(e *Envelope) ([]byte, error) { return e.Encode() }
func (binaryCodec) Decode(b []byte) (*Envelope, error) { return Parse(b) }
func (c binaryCodec) EncodeWithProfile(e *Envelope, _ *FormatProfile, _ RenderContext) ([]byte, error) {
	return c.Encode(e)
}
func (c binaryCodec) DecodeWithProfile(b []byte, _ *FormatProfile) (*Envelope, ExtensionBag, error) {
	env, err := c.Decode(b)
	return env, nil, err
}

type jsonEnvelope struct {
	Version       uint8  `json:"version"`
	Flags         uint16 `json:"flags"`
	SuiteID       uint16 `json:"suite_id"`
	KeyID         string `json:"key_id"`
	KeyVersion    uint32 `json:"key_version"`
	PolicyVersion uint32 `json:"policy_version"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	Tag           string `json:"tag"`
	AADHash       string `json:"aad_hash,omitempty"`
}
type jsonCodec struct{}

func (jsonCodec) ID() FormatID { return FormatJSONV1 }
func (jsonCodec) Match(b []byte) bool {
	return len(bytes.TrimSpace(b)) > 0 && bytes.TrimSpace(b)[0] == '{'
}
func (jsonCodec) Encode(e *Envelope) ([]byte, error) {
	out := jsonEnvelope{Version: e.Version, Flags: e.Flags, SuiteID: uint16(e.SuiteID), KeyID: string(e.KeyID), KeyVersion: e.KeyVersion, PolicyVersion: e.PolicyVersion, Nonce: base64.RawStdEncoding.EncodeToString(e.Nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(e.Ciphertext), Tag: base64.RawStdEncoding.EncodeToString(e.Tag)}
	if e.SuiteID.AuthenticatesAAD() {
		out.AADHash = base64.RawStdEncoding.EncodeToString(e.AADHash[:])
	}
	return json.Marshal(out)
}
func (c jsonCodec) EncodeWithProfile(e *Envelope, _ *FormatProfile, _ RenderContext) ([]byte, error) {
	return c.Encode(e)
}
func (jsonCodec) Decode(b []byte) (*Envelope, error) {
	var v jsonEnvelope
	d := json.NewDecoder(bytes.NewReader(b))
	if d.Decode(&v) != nil || d.Decode(&struct{}{}) != io.EOF || v.Version != Version1 {
		return nil, ErrInvalid
	}
	n, e1 := base64.RawStdEncoding.DecodeString(v.Nonce)
	c, e2 := base64.RawStdEncoding.DecodeString(v.Ciphertext)
	t, e3 := base64.RawStdEncoding.DecodeString(v.Tag)
	suite := aead.SuiteID(v.SuiteID)
	var h []byte
	var e4 error
	if suite.AuthenticatesAAD() {
		h, e4 = base64.RawStdEncoding.DecodeString(v.AADHash)
	}
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || (suite.AuthenticatesAAD() && len(h) != 32) {
		return nil, ErrInvalid
	}
	var ah [32]byte
	copy(ah[:], h)
	e := &Envelope{Version: v.Version, Flags: v.Flags, SuiteID: suite, KeyID: []byte(v.KeyID), KeyVersion: v.KeyVersion, PolicyVersion: v.PolicyVersion, Nonce: n, Ciphertext: c, Tag: t, AADHash: ah}
	raw, err := e.Encode()
	if err != nil {
		return nil, ErrInvalid
	}
	return Parse(raw)
}
func (c jsonCodec) DecodeWithProfile(b []byte, _ *FormatProfile) (*Envelope, ExtensionBag, error) {
	env, err := c.Decode(b)
	if err != nil {
		return nil, nil, err
	}
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	extensions := ExtensionBag{}
	for k, v := range obj {
		if !isCoreJSONField(k) {
			extensions[k] = v
		}
	}
	return env, extensions, nil
}

type configurableJSONCodec struct{}

func (configurableJSONCodec) ID() FormatID { return FormatConfigurableJSONV1 }
func (configurableJSONCodec) Match(b []byte) bool {
	return jsonCodec{}.Match(b)
}
func (c configurableJSONCodec) Encode(e *Envelope) ([]byte, error) {
	return c.EncodeWithProfile(e, BuiltinProfile(FormatConfigurableJSONV1), RenderContext{})
}
func (c configurableJSONCodec) Decode(b []byte) (*Envelope, error) {
	env, _, err := c.DecodeWithProfile(b, BuiltinProfile(FormatConfigurableJSONV1))
	return env, err
}
func (configurableJSONCodec) EncodeWithProfile(e *Envelope, profile *FormatProfile, ctx RenderContext) ([]byte, error) {
	if profile == nil {
		profile = BuiltinProfile(FormatConfigurableJSONV1)
	}
	mappings := profile.FieldMappings
	if len(mappings) == 0 {
		mappings = DefaultJSONMappings()
	}
	obj := map[string]any{}
	for _, m := range mappings {
		if strings.TrimSpace(m.Path) == "" || strings.TrimSpace(m.Source) == "" {
			continue
		}
		value, ok, err := renderMappingValue(e, m, ctx)
		if err != nil {
			return nil, err
		}
		if !ok {
			if sourceOptionalForEnvelope(e, m.Source) {
				continue
			}
			if m.Required {
				return nil, fmt.Errorf("envelope: required mapping %s missing", m.Source)
			}
			continue
		}
		if err := setJSONPath(obj, m.Path, value); err != nil {
			return nil, err
		}
	}
	for _, ext := range profile.Extensions {
		name := strings.TrimSpace(ext.Name)
		if name == "" {
			continue
		}
		if _, ok := ctx.Extensions[name]; ok {
			continue
		}
		if ext.Required && strings.TrimSpace(ext.DefaultValue) == "" {
			return nil, fmt.Errorf("envelope: required extension %s missing", name)
		}
		if strings.TrimSpace(ext.DefaultValue) != "" {
			if err := setJSONPath(obj, "$."+name, typedDefault(ext.Type, ext.DefaultValue)); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(obj)
}

func sourceOptionalForEnvelope(e *Envelope, source string) bool {
	return source == "core.aad_hash" && e != nil && !e.SuiteID.AuthenticatesAAD()
}
func (configurableJSONCodec) DecodeWithProfile(b []byte, profile *FormatProfile) (*Envelope, ExtensionBag, error) {
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, nil, ErrInvalid
	}
	if profile == nil {
		profile = BuiltinProfile(FormatConfigurableJSONV1)
	}
	mappings := profile.FieldMappings
	if len(mappings) == 0 {
		mappings = DefaultJSONMappings()
	}
	core := map[string]any{}
	extensions := ExtensionBag{}
	for _, m := range mappings {
		v, ok := getJSONPath(obj, m.Path)
		if !ok {
			if m.Source == "core.aad_hash" {
				continue
			}
			if m.Required {
				return nil, nil, ErrInvalid
			}
			if strings.TrimSpace(m.DefaultValue) == "" {
				continue
			}
			v = m.DefaultValue
		}
		if strings.HasPrefix(m.Source, "core.") {
			core[strings.TrimPrefix(m.Source, "core.")] = v
			continue
		}
		if strings.HasPrefix(m.Source, "extension.") {
			extensions[strings.TrimPrefix(m.Source, "extension.")] = v
		}
	}
	normalized, err := coreEnvelopeFromMap(core, mappings)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	env, err := jsonCodec{}.Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	return env, extensions, nil
}

func renderMappingValue(e *Envelope, m FieldMapping, ctx RenderContext) (any, bool, error) {
	source := strings.TrimSpace(m.Source)
	var value any
	switch source {
	case "core.version":
		value = e.Version
	case "core.flags":
		value = e.Flags
	case "core.suite_id":
		value = uint16(e.SuiteID)
	case "core.key_id":
		value = string(e.KeyID)
	case "core.key_version":
		value = e.KeyVersion
	case "core.policy_version":
		value = e.PolicyVersion
	case "core.nonce":
		value = e.Nonce
	case "core.ciphertext":
		value = e.Ciphertext
	case "core.tag":
		value = e.Tag
	case "core.aad_hash":
		if !e.SuiteID.AuthenticatesAAD() {
			return nil, false, nil
		}
		value = e.AADHash[:]
	case "derived.algorithm_name":
		value = suiteName(e.SuiteID)
	default:
		if strings.HasPrefix(source, "extension.") {
			key := strings.TrimPrefix(source, "extension.")
			v, ok := ctx.Extensions[key]
			if !ok && strings.TrimSpace(m.DefaultValue) != "" {
				return typedDefault("", m.DefaultValue), true, nil
			}
			return v, ok, nil
		}
		return nil, false, fmt.Errorf("envelope: unsupported mapping source %s", source)
	}
	return encodeMappedValue(value, m.Encoding), true, nil
}

func encodeMappedValue(v any, encoding string) any {
	b, ok := v.([]byte)
	if !ok {
		return v
	}
	switch encoding {
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(b)
	case "base64", "base64std":
		return base64.StdEncoding.EncodeToString(b)
	default:
		return base64.RawStdEncoding.EncodeToString(b)
	}
}

func coreEnvelopeFromMap(core map[string]any, mappings []FieldMapping) (jsonEnvelope, error) {
	var out jsonEnvelope
	var err error
	out.Version, err = uint8FromAny(core["version"])
	if err != nil {
		return out, err
	}
	out.Flags, err = uint16FromAny(core["flags"])
	if err != nil {
		return out, err
	}
	out.SuiteID, err = uint16FromAny(core["suite_id"])
	if err != nil {
		return out, err
	}
	out.KeyID, _ = core["key_id"].(string)
	out.KeyVersion, err = uint32FromAny(core["key_version"])
	if err != nil {
		return out, err
	}
	out.PolicyVersion, err = uint32FromAny(core["policy_version"])
	if err != nil {
		return out, err
	}
	out.Nonce, err = encodedString(core["nonce"], encodingFor("core.nonce", mappings))
	if err != nil {
		return out, err
	}
	out.Ciphertext, err = encodedString(core["ciphertext"], encodingFor("core.ciphertext", mappings))
	if err != nil {
		return out, err
	}
	out.Tag, err = encodedString(core["tag"], encodingFor("core.tag", mappings))
	if err != nil {
		return out, err
	}
	if aead.SuiteID(out.SuiteID).AuthenticatesAAD() {
		out.AADHash, err = encodedString(core["aad_hash"], encodingFor("core.aad_hash", mappings))
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func encodedString(v any, encoding string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("envelope: expected encoded string")
	}
	var b []byte
	var err error
	switch encoding {
	case "base64url":
		b, err = base64.RawURLEncoding.DecodeString(s)
	case "base64", "base64std":
		b, err = base64.StdEncoding.DecodeString(s)
	default:
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func encodingFor(source string, mappings []FieldMapping) string {
	for _, m := range mappings {
		if m.Source == source {
			return m.Encoding
		}
	}
	return "base64raw"
}

func setJSONPath(obj map[string]any, path string, value any) error {
	parts, err := pathParts(path)
	if err != nil {
		return err
	}
	cur := obj
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = value
			return nil
		}
		next, _ := cur[p].(map[string]any)
		if next == nil {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	return nil
}

func getJSONPath(obj map[string]any, path string) (any, bool) {
	parts, err := pathParts(path)
	if err != nil {
		return nil, false
	}
	var cur any = obj
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func pathParts(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "$.") {
		return nil, fmt.Errorf("envelope: path must start with $.")
	}
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("envelope: empty path segment")
		}
	}
	return parts, nil
}

func typedDefault(t, raw string) any {
	switch t {
	case "number":
		if n, err := strconv.ParseFloat(raw, 64); err == nil {
			return n
		}
	case "boolean":
		if b, err := strconv.ParseBool(raw); err == nil {
			return b
		}
	case "json":
		var v any
		if json.Unmarshal([]byte(raw), &v) == nil {
			return v
		}
	}
	return raw
}

func uint8FromAny(v any) (uint8, error) {
	n, err := uint64FromAny(v)
	if err != nil || n > uint64(^uint8(0)) {
		return 0, fmt.Errorf("envelope: expected uint8")
	}
	return uint8(n), nil
}
func uint16FromAny(v any) (uint16, error) {
	n, err := uint64FromAny(v)
	if err != nil || n > uint64(^uint16(0)) {
		return 0, fmt.Errorf("envelope: expected uint16")
	}
	return uint16(n), nil
}
func uint32FromAny(v any) (uint32, error) {
	n, err := uint64FromAny(v)
	if err != nil || n > uint64(^uint32(0)) {
		return 0, fmt.Errorf("envelope: expected uint32")
	}
	return uint32(n), nil
}
func uint64FromAny(v any) (uint64, error) {
	switch x := v.(type) {
	case float64:
		if x < 0 || math.Trunc(x) != x || x > float64(^uint64(0)) {
			return 0, fmt.Errorf("envelope: expected integer")
		}
		return uint64(x), nil
	case uint8:
		return uint64(x), nil
	case uint16:
		return uint64(x), nil
	case uint32:
		return uint64(x), nil
	case uint64:
		return x, nil
	case int:
		return uint64(x), nil
	case string:
		return strconv.ParseUint(x, 10, 64)
	default:
		return 0, fmt.Errorf("envelope: expected number")
	}
}

func suiteName(s aead.SuiteID) string {
	switch s {
	case aead.SuiteAES256GCM:
		return "AES_256_GCM"
	case aead.SuiteSM4GCM:
		return "SM4_GCM"
	case aead.SuiteAES256ECB:
		return "AES_256_ECB"
	case aead.SuiteSM4ECB:
		return "SM4_ECB"
	default:
		return fmt.Sprintf("0x%04x", uint16(s))
	}
}

func isCoreJSONField(k string) bool {
	switch k {
	case "version", "flags", "suite_id", "key_id", "key_version", "policy_version", "nonce", "ciphertext", "tag", "aad_hash":
		return true
	default:
		return false
	}
}

// base64Codec and pemCodec have been removed. Built-in adapters are binary,
// canonical JSON, and configurable JSON profile rendering.

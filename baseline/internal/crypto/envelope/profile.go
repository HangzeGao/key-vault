package envelope

// RenderContext carries request-scoped values that may be rendered into
// external envelope formats. Extensions are never part of the core AEAD
// authentication boundary in this baseline.
type RenderContext struct {
	Extensions map[string]any
}

// ExtensionBag contains non-core fields parsed from an external envelope.
type ExtensionBag map[string]any

// FormatProfile describes a tenant or partner facing envelope format.
// FormatID is the name clients request. Adapter is the registered renderer
// implementation, for example configurable-json-v1.
type FormatProfile struct {
	FormatID      FormatID
	Adapter       FormatID
	FieldMappings []FieldMapping
	Extensions    []ExtensionField
	Description   string
}

// FieldMapping maps an external field path to a core, derived, or extension
// value. Only core.* values can reconstruct the immutable CoreEnvelope.
type FieldMapping struct {
	Path         string
	Source       string
	Required     bool
	Encoding     string
	DefaultValue string
}

type ExtensionField struct {
	Name         string
	Type         string
	Required     bool
	DefaultValue string
	Description  string
}

func BuiltinProfile(format FormatID) *FormatProfile {
	switch format {
	case FormatKVLTBinaryV1:
		return &FormatProfile{FormatID: FormatKVLTBinaryV1, Adapter: FormatKVLTBinaryV1}
	case FormatJSONV1:
		return &FormatProfile{FormatID: FormatJSONV1, Adapter: FormatJSONV1}
	case FormatConfigurableJSONV1:
		return &FormatProfile{FormatID: FormatConfigurableJSONV1, Adapter: FormatConfigurableJSONV1, FieldMappings: DefaultJSONMappings()}
	default:
		return nil
	}
}

func DefaultJSONMappings() []FieldMapping {
	return []FieldMapping{
		{Path: "$.version", Source: "core.version", Required: true},
		{Path: "$.flags", Source: "core.flags", Required: true},
		{Path: "$.suite_id", Source: "core.suite_id", Required: true},
		{Path: "$.key_id", Source: "core.key_id", Required: true},
		{Path: "$.key_version", Source: "core.key_version", Required: true},
		{Path: "$.policy_version", Source: "core.policy_version", Required: true},
		{Path: "$.nonce", Source: "core.nonce", Required: true, Encoding: "base64raw"},
		{Path: "$.ciphertext", Source: "core.ciphertext", Required: true, Encoding: "base64raw"},
		{Path: "$.tag", Source: "core.tag", Required: true, Encoding: "base64raw"},
		{Path: "$.aad_hash", Source: "core.aad_hash", Required: false, Encoding: "base64raw"},
	}
}

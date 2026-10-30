package controlplane

import "gopkg.in/yaml.v3"

type configurationDocumentNodes map[string]configurationDocumentNode
type configurationDocumentProfiles map[string]configurationDocumentRules

// yaml.v3 checks mapping keys pairwise before decoding a Go map. Decode the
// bounded large maps entry by entry instead, with linear duplicate detection.
// Explicit field checks retain KnownFields behavior inside custom unmarshallers.
func decodeConfigurationEntries[T any](n *yaml.Node, fields map[string]bool) (map[string]T, error) {
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" || len(n.Content)%2 != 0 || len(n.Content)/2 > configurationNodeLimit {
		return nil, errConfigurationDocument
	}
	out := make(map[string]T, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || value.Kind != yaml.MappingNode || value.Tag != "!!map" || len(value.Content)%2 != 0 {
			return nil, errConfigurationDocument
		}
		if _, exists := out[key.Value]; exists {
			return nil, errConfigurationDocument
		}
		for j := 0; j < len(value.Content); j += 2 {
			field := value.Content[j]
			if field.Kind != yaml.ScalarNode || field.Tag != "!!str" || !fields[field.Value] {
				return nil, errConfigurationDocument
			}
		}
		var entry T
		if value.Decode(&entry) != nil {
			return nil, errConfigurationDocument
		}
		out[key.Value] = entry
	}
	return out, nil
}

func (m *configurationDocumentNodes) UnmarshalYAML(n *yaml.Node) error {
	entries, err := decodeConfigurationEntries[configurationDocumentNode](n, map[string]bool{
		"name": true, "endpoint": true, "server_name": true, "enabled": true,
		"mode": true, "version": true, "profile": true, "omitted_fields": true,
	})
	if err == nil {
		*m = entries
	}
	return err
}

func (m *configurationDocumentProfiles) UnmarshalYAML(n *yaml.Node) error {
	entries, err := decodeConfigurationEntries[configurationDocumentRules](n, map[string]bool{"config": true, "omitted_fields": true})
	if err == nil {
		*m = entries
	}
	return err
}

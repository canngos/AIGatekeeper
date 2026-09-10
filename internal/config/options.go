package config

import (
	"sort"

	"gopkg.in/yaml.v3"
)

// DetectorOptions are one detector's settings inside a rule.
//
// They stay generic because every detector defines its own, but a generic
// map marshals with its keys in alphabetical order, which turns a readable
// entry into "length, note, prefix". The file is meant to be read and
// reviewed in a pull request, so known keys are written in the order they
// make sense in and anything unrecognised follows, alphabetically.
type DetectorOptions map[string]any

// optionKeyOrder is the preferred order, applied at any depth. The key sets
// of the different levels do not overlap, so one table serves all of them.
var optionKeyOrder = []string{
	"enabled",
	"prefixes", "min_length", "max_length",
	"prefix", "length", "note",
	"min_entropy", "require_context",
}

// UnmarshalYAML implements yaml.Unmarshaler.
//
// Without it the decoder carries this named type down into every nested
// mapping, so a detector reading its own options would be handed a
// config.DetectorOptions where it expects a plain map and would reject it.
// The type exists only to control how options are written back.
func (o *DetectorOptions) UnmarshalYAML(node *yaml.Node) error {
	var m map[string]any
	if err := node.Decode(&m); err != nil {
		return err
	}
	*o = m
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (o DetectorOptions) MarshalYAML() (any, error) {
	if len(o) == 0 {
		return nil, nil
	}
	return orderedNode(map[string]any(o))
}

func orderedNode(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range orderedKeys(t) {
			key := &yaml.Node{}
			if err := key.Encode(k); err != nil {
				return nil, err
			}
			val, err := orderedNode(t[k])
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, key, val)
		}
		return n, nil
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range t {
			val, err := orderedNode(item)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, val)
		}
		return n, nil
	default:
		n := &yaml.Node{}
		if err := n.Encode(v); err != nil {
			return nil, err
		}
		return n, nil
	}
}

func orderedKeys(m map[string]any) []string {
	rank := func(k string) int {
		for i, want := range optionKeyOrder {
			if k == want {
				return i
			}
		}
		return len(optionKeyOrder)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank(keys[i]), rank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	return keys
}

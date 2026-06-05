package a2a

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
)

// ExtractTaskFields walks an A2A task envelope and returns inspectable
// string leaves keyed by dotted path under "params" or "result".
func ExtractTaskFields(env *TaskEnvelope) []detect.Field {
	if env == nil {
		return nil
	}
	out := make([]detect.Field, 0, 8)
	if len(env.Params) > 0 {
		var v any
		if err := json.Unmarshal(env.Params, &v); err == nil {
			out = walk("params", v, out)
		}
	}
	if len(env.Result) > 0 {
		var v any
		if err := json.Unmarshal(env.Result, &v); err == nil {
			out = walk("result", v, out)
		}
	}
	if env.Error != nil && env.Error.Message != "" {
		out = append(out, detect.Field{Name: "error.message", Value: env.Error.Message})
	}
	return out
}

// ExtractCardFields returns inspectable strings drawn from an agent
// card. Used for tool-poisoning-style detection on card description
// and skill descriptions at discovery time.
func ExtractCardFields(c *AgentCard) []detect.Field {
	if c == nil {
		return nil
	}
	out := []detect.Field{}
	if c.Name != "" {
		out = append(out, detect.Field{Name: "card.name", Value: c.Name})
	}
	if c.Description != "" {
		out = append(out, detect.Field{Name: "card.description", Value: c.Description})
	}
	if c.URL != "" {
		out = append(out, detect.Field{Name: "card.url", Value: c.URL})
	}
	if c.Provider != nil {
		if c.Provider.Organization != "" {
			out = append(out, detect.Field{Name: "card.provider.organization", Value: c.Provider.Organization})
		}
	}
	for i, sk := range c.Skills {
		base := fmt.Sprintf("card.skills.%d", i)
		if sk.Name != "" {
			out = append(out, detect.Field{Name: base + ".name", Value: sk.Name})
		}
		if sk.Description != "" {
			out = append(out, detect.Field{Name: base + ".description", Value: sk.Description})
		}
		for j, tag := range sk.Tags {
			out = append(out, detect.Field{Name: fmt.Sprintf("%s.tags.%d", base, j), Value: tag})
		}
	}
	return out
}

// MessageFromTaskEnvelope converts a parsed envelope and raw bytes
// into the event.Message form used by the control plane.
func MessageFromTaskEnvelope(env *TaskEnvelope, raw []byte) event.Message {
	msg := event.Message{
		Method: env.Method,
		Raw:    string(raw),
	}
	if len(env.ID) > 0 {
		msg.ID = strings.Trim(string(env.ID), `"`)
	}
	if len(env.Params) > 0 {
		var m map[string]any
		if err := json.Unmarshal(env.Params, &m); err == nil {
			msg.Params = m
		}
	}
	if len(env.Result) > 0 {
		var m map[string]any
		if err := json.Unmarshal(env.Result, &m); err == nil {
			msg.Result = m
		}
	}
	if env.Error != nil {
		msg.Error = map[string]any{
			"code":    env.Error.Code,
			"message": env.Error.Message,
		}
	}
	return msg
}

func walk(path string, v any, out []detect.Field) []detect.Field {
	switch t := v.(type) {
	case string:
		out = append(out, detect.Field{Name: path, Value: t})
	case map[string]any:
		for k, child := range t {
			out = walk(joinPath(path, k), child, out)
		}
	case []any:
		for i, child := range t {
			out = walk(joinPath(path, fmt.Sprintf("%d", i)), child, out)
		}
	}
	return out
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

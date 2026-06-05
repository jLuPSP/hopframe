package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
)

// ExtractFields walks a parsed MCP envelope and returns the inspectable
// string fields a detector should scan. Field names use dot/index paths
// rooted at "params" or "result".
//
// We intentionally over-collect: it is cheaper to feed every leaf string
// through regex than to maintain a method-by-method allowlist. Detectors
// scope themselves with field globs.
func ExtractFields(env *Envelope) []detect.Field {
	if env == nil {
		return nil
	}
	out := make([]detect.Field, 0, 8)
	if len(env.Params) > 0 {
		var v any
		if err := json.Unmarshal(env.Params, &v); err == nil {
			out = walkValue("params", v, out)
		}
	}
	if len(env.Result) > 0 {
		var v any
		if err := json.Unmarshal(env.Result, &v); err == nil {
			out = walkValue("result", v, out)
		}
	}
	if env.Error != nil && env.Error.Message != "" {
		out = append(out, detect.Field{Name: "error.message", Value: env.Error.Message})
	}
	return out
}

func walkValue(path string, v any, out []detect.Field) []detect.Field {
	switch t := v.(type) {
	case string:
		out = append(out, detect.Field{Name: path, Value: t})
	case map[string]any:
		for k, child := range t {
			out = walkValue(joinPath(path, k), child, out)
		}
	case []any:
		for i, child := range t {
			out = walkValue(joinPath(path, fmt.Sprintf("%d", i)), child, out)
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

// MessageFromEnvelope converts a parsed envelope and its raw bytes into
// the event.Message form carried in events. Params and Result are decoded
// into map[string]any when possible; otherwise they are dropped from the
// structured form (the raw body is always preserved).
func MessageFromEnvelope(env *Envelope, raw []byte) event.Message {
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

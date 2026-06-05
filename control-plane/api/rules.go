package api

import (
	"net/http"
	"sort"
	"sync"

	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

// /v1/rules exposes the loaded detection-content rule pack as JSON so
// an evaluator can see what the system actually catches without
// reading YAML on disk. Backed by the same content bundle the OTA
// channel serves; refreshed when SetContentRoot or RefreshContent is
// called.

// ruleSummary is the wire shape consumed by the UI's /rules page.
// Patterns and field globs come along so the UI can show the actual
// matcher when a user expands a row.
type ruleSummary struct {
	ID            string         `json:"id"`
	Category      string         `json:"category"`
	Severity      event.Severity `json:"severity"`
	Mode          string         `json:"mode"`
	Description   string         `json:"description,omitempty"`
	Targets       []string       `json:"targets,omitempty"`
	Directions    []string       `json:"directions,omitempty"`
	Fields        []string       `json:"fields,omitempty"`
	Patterns      []string       `json:"patterns,omitempty"`
	Confidence    float64        `json:"confidence,omitempty"`
	CaseSensitive bool           `json:"case_sensitive,omitempty"`
	ContentHash   string         `json:"content_hash,omitempty"`
}

type rulesCache struct {
	mu      sync.Mutex
	root    string
	rules   []ruleSummary
	loaded  bool
	loadErr error
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	if s.content == nil {
		http.Error(w, "content not configured", http.StatusNotFound)
		return
	}
	rules, err := s.loadRulesSummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	categories := make(map[string]int, 8)
	for _, r := range rules {
		categories[r.Category]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":      rules,
		"count":      len(rules),
		"categories": categories,
		"version":    s.activeContentVersion(),
	})
}

func (s *Server) loadRulesSummary() ([]ruleSummary, error) {
	if s.rulesCache == nil {
		s.rulesCache = &rulesCache{}
	}
	c := s.rulesCache
	c.mu.Lock()
	defer c.mu.Unlock()
	root := s.content.root
	if c.loaded && c.root == root && c.loadErr == nil {
		return c.rules, nil
	}
	rs, err := ruleset.LoadDir(root)
	if err != nil {
		c.loadErr = err
		return nil, err
	}
	out := make([]ruleSummary, 0, rs.Len())
	for _, r := range rs.Rules() {
		dirs := make([]string, 0, len(r.Directions))
		for _, d := range r.Directions {
			dirs = append(dirs, string(d))
		}
		out = append(out, ruleSummary{
			ID:            r.ID,
			Category:      r.Category,
			Severity:      r.Severity,
			Mode:          string(r.Mode),
			Description:   r.Description,
			Targets:       r.Targets,
			Directions:    dirs,
			Fields:        r.FieldGlobs,
			Patterns:      r.Patterns,
			Confidence:    r.Confidence,
			CaseSensitive: r.CaseSensitive,
			ContentHash:   r.ContentHash(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	c.rules = out
	c.root = root
	c.loaded = true
	c.loadErr = nil
	return out, nil
}

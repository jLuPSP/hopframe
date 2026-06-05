// Command stub-a2a-server is a minimal A2A peer used as a fixture
// in development and tests. It serves a static agent card at
// /.well-known/agent.json and accepts task envelopes at /, returning
// canned task results.
//
// It maintains an in-memory task table so tasks/get returns a
// consistent state for a given task id across calls. State transitions
// are: submitted → working → completed.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/pkg/a2a"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type task struct {
	id       string
	state    string
	created  time.Time
	updated  time.Time
	contents []map[string]any
}

type server struct {
	mu    sync.Mutex
	tasks map[string]*task
}

func main() {
	buildinfo.MaybePrint("stub-a2a-server", version, commit, date)
	addr := flag.String("addr", ":8089", "listen address")
	flag.Parse()
	s := &server{tasks: make(map[string]*task)}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/.well-known/agent.json", s.handleCard)
	mux.HandleFunc("/", s.handleTask)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("stub-a2a-server listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("stub-a2a-server: %v", err)
	}
}

func (s *server) handleCard(w http.ResponseWriter, _ *http.Request) {
	card := a2a.AgentCard{
		Name:        "hopframe-stub-agent",
		Description: "Demo A2A peer used by Hopframe development.",
		URL:         "http://127.0.0.1:8089",
		Version:     "0.1.0",
		Provider: &a2a.Provider{
			Organization: "ExampleOrg",
			URL:          "https://example.com",
		},
		Capabilities: &a2a.Capabilities{Streaming: false, PushNotifications: false},
		Skills: []a2a.Skill{
			{ID: "echo", Name: "echo", Description: "Echo the input back as a task result."},
			{ID: "summarize", Name: "summarize", Description: "Summarize provided text."},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(card)
}

func (s *server) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	env, err := a2a.ParseTask(body)
	if err != nil {
		http.Error(w, "parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp := a2a.TaskEnvelope{JSONRPC: a2a.JSONRPCVersion, ID: env.ID}
	switch env.Method {
	case a2a.MethodTasksSend, a2a.MethodTasksSendSubscribe:
		s.mu.Lock()
		var params struct {
			ID      string         `json:"id"`
			Message map[string]any `json:"message,omitempty"`
		}
		_ = json.Unmarshal(env.Params, &params)
		if params.ID == "" {
			params.ID = "stub-task-" + time.Now().UTC().Format("150405.000000")
		}
		t, ok := s.tasks[params.ID]
		if !ok {
			t = &task{id: params.ID, state: "submitted", created: time.Now().UTC()}
			s.tasks[params.ID] = t
		}
		t.state = "completed"
		t.updated = time.Now().UTC()
		if params.Message != nil {
			t.contents = append(t.contents, params.Message)
		}
		body, _ := json.Marshal(map[string]any{
			"id":     t.id,
			"status": map[string]any{"state": t.state, "timestamp": t.updated.Format(time.RFC3339)},
			"messages": []map[string]any{
				{"role": "agent", "parts": []map[string]any{{"type": "text", "text": "stub completed"}}},
			},
		})
		resp.Result = body
		s.mu.Unlock()
	case a2a.MethodTasksGet:
		s.mu.Lock()
		var params struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(env.Params, &params)
		t, ok := s.tasks[params.ID]
		if !ok {
			resp.Error = &a2a.Error{Code: -32602, Message: "no such task " + params.ID}
		} else {
			body, _ := json.Marshal(map[string]any{
				"id":     t.id,
				"status": map[string]any{"state": t.state, "timestamp": t.updated.Format(time.RFC3339)},
			})
			resp.Result = body
		}
		s.mu.Unlock()
	case a2a.MethodTasksCancel:
		s.mu.Lock()
		var params struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(env.Params, &params)
		if t, ok := s.tasks[params.ID]; ok {
			t.state = "canceled"
			t.updated = time.Now().UTC()
		}
		resp.Result = json.RawMessage(`{"status":"canceled"}`)
		s.mu.Unlock()
	default:
		resp.Error = &a2a.Error{Code: -32601, Message: "method not implemented in stub: " + env.Method}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}

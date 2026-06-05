package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// contentBundle exposes a versioned set of detection-content files
// to sensors over HTTP, so detection-content updates do not require a
// sensor binary redeploy. The bundle is loaded from disk and refreshed
// on a configurable interval; the version is the content hash of all
// files combined.
//
// On each refresh the manifest is recomputed atomically. Sensors poll
// /v1/content/manifest, compare the version they have applied, and
// fetch any files whose individual hashes have changed.
type contentBundle struct {
	mu        sync.RWMutex
	root      string
	files     map[string]contentFile
	manifest  contentManifest
	updatedAt time.Time
}

type contentFile struct {
	Name string
	Body []byte
	Hash string
}

type contentManifest struct {
	Version   string                 `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	Files     []contentManifestEntry `json:"files"`
}

type contentManifestEntry struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
	Size int    `json:"size"`
}

// SetContentRoot enables OTA content delivery from the given directory
// (typically the bundled content/ tree). Pass an empty string to
// disable. The directory is scanned recursively for *.yaml files; each
// becomes one entry in the manifest. The root is read again on each
// call to RefreshContent.
func (s *Server) SetContentRoot(root string) error {
	if root == "" {
		s.content = nil
		return nil
	}
	bundle := &contentBundle{root: root}
	if err := bundle.refresh(); err != nil {
		return err
	}
	s.content = bundle
	return nil
}

// RefreshContent re-reads the content directory and recomputes the
// manifest. Operators wire this to a SIGHUP or call it on a timer to
// pick up edits without restarting the control plane.
func (s *Server) RefreshContent() error {
	if s.content == nil {
		return errors.New("content root not set")
	}
	return s.content.refresh()
}

func (b *contentBundle) refresh() error {
	files := make(map[string]contentFile)
	err := filepath.Walk(b.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(b.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		sum := sha256.Sum256(body)
		files[rel] = contentFile{Name: rel, Body: body, Hash: hex.EncodeToString(sum[:])}
		return nil
	})
	if err != nil {
		return err
	}
	entries := make([]contentManifestEntry, 0, len(files))
	for _, f := range files {
		entries = append(entries, contentManifestEntry{Name: f.Name, Hash: f.Hash, Size: len(f.Body)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	mh := sha256.New()
	for _, e := range entries {
		mh.Write([]byte(e.Name))
		mh.Write([]byte{0})
		mh.Write([]byte(e.Hash))
		mh.Write([]byte{0})
	}
	now := time.Now().UTC()
	mf := contentManifest{
		Version:   hex.EncodeToString(mh.Sum(nil))[:16],
		UpdatedAt: now,
		Files:     entries,
	}

	b.mu.Lock()
	b.files = files
	b.manifest = mf
	b.updatedAt = now
	b.mu.Unlock()
	return nil
}

func (b *contentBundle) version() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.manifest.Version
}

func (b *contentBundle) snapshot() (contentManifest, map[string]contentFile) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cp := make(map[string]contentFile, len(b.files))
	for k, v := range b.files {
		cp[k] = v
	}
	return b.manifest, cp
}

func (s *Server) handleContentManifest(w http.ResponseWriter, _ *http.Request) {
	if s.content == nil {
		http.Error(w, "content not configured", http.StatusNotFound)
		return
	}
	mf, _ := s.content.snapshot()
	writeJSON(w, http.StatusOK, mf)
}

func (s *Server) handleContentFile(w http.ResponseWriter, r *http.Request) {
	if s.content == nil {
		http.Error(w, "content not configured", http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/content/")
	if rest == r.URL.Path || rest == "" || rest == "manifest" {
		http.Error(w, "expected /v1/content/{name}", http.StatusBadRequest)
		return
	}
	if strings.Contains(rest, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	_, files := s.content.snapshot()
	f, ok := files[rest]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("X-Hopframe-Content-Hash", f.Hash)
	_, _ = w.Write(f.Body)
}

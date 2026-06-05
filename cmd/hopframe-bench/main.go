// Command hopframe-bench is the public benchmark suite Hopframe ships
// against. The PRD calls for "public benchmark suite: precision/recall
// numbers on a published test set, refreshed monthly." This is the
// primitive behind that promise.
//
// Two modes:
//
//	--mode latency  : pump synthetic envelopes through the pipeline
//	                  and report p50/p90/p99 latency + throughput.
//	--mode corpus   : run the pipeline against a labeled JSONL corpus
//	                  and report precision/recall/F1 per category.
//
// Corpus format: one JSON object per line, schema:
//
//	{"id": "...", "category": "prompt-injection", "label": "malicious",
//	 "text": "..."}
//
// `label` is "malicious" or "benign". `category` is the expected
// finding category for malicious examples (ignored on benign).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/event"
	"github.com/jlupsp/hopframe/pkg/ruleset"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("hopframe-bench", version, commit, date)
	mode := flag.String("mode", "latency", "latency | corpus")
	rulesDir := flag.String("rules", "content", "rule pack directory")
	count := flag.Int("count", 10000, "latency-mode evaluations")
	parallel := flag.Int("parallel", 4, "latency-mode workers")
	corpusPath := flag.String("corpus", "bench/corpus/v1.jsonl", "corpus-mode JSONL path")
	classifier := flag.Bool("classifier", true, "include the heuristic classifier (Layer 2)")
	flag.Parse()

	rs, err := ruleset.LoadDir(*rulesDir)
	if err != nil {
		log.Fatalf("bench: rules: %v", err)
	}
	detectors := []detect.Detector{rs}
	if *classifier {
		detectors = append(detectors, &detect.HeuristicClassifier{})
	}
	log.Printf("loaded %d rules; %d detectors", rs.Len(), len(detectors))

	switch *mode {
	case "latency":
		runLatency(detectors, *count, *parallel)
	case "corpus":
		runCorpus(detectors, *corpusPath)
	default:
		log.Fatalf("bench: unknown mode %q", *mode)
	}
}

// --- latency mode ---

func runLatency(detectors []detect.Detector, count, parallel int) {
	corpus := buildSyntheticCorpus()
	jobs := make(chan int, parallel*2)
	results := make(chan time.Duration, count)
	for w := 0; w < parallel; w++ {
		go func() {
			ctx := context.Background()
			for idx := range jobs {
				value := corpus[idx%len(corpus)]
				start := time.Now()
				v := &detect.Verdict{}
				in := &detect.Input{
					Method:    "tools/call",
					Direction: event.DirectionInbound,
					Fields:    []detect.Field{{Name: "params.text", Value: value}},
				}
				for _, d := range detectors {
					_ = d.Detect(ctx, in, v)
				}
				results <- time.Since(start)
			}
		}()
	}
	go func() {
		for i := 0; i < count; i++ {
			jobs <- i
		}
		close(jobs)
	}()
	durs := make([]time.Duration, 0, count)
	overall := time.Now()
	for i := 0; i < count; i++ {
		durs = append(durs, <-results)
	}
	elapsed := time.Since(overall)
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	fmt.Println("---- pipeline latency ----")
	fmt.Printf("count        %d\n", len(durs))
	fmt.Printf("workers      %d\n", parallel)
	fmt.Printf("throughput   %.0f evals/sec\n", float64(len(durs))/elapsed.Seconds())
	fmt.Printf("p50          %s\n", percentile(durs, 0.50))
	fmt.Printf("p90          %s\n", percentile(durs, 0.90))
	fmt.Printf("p99          %s\n", percentile(durs, 0.99))
	fmt.Printf("p99.9        %s\n", percentile(durs, 0.999))
	fmt.Printf("max          %s\n", durs[len(durs)-1])
}

func percentile(durs []time.Duration, p float64) time.Duration {
	if len(durs) == 0 {
		return 0
	}
	idx := int(float64(len(durs)-1) * p)
	return durs[idx]
}

func buildSyntheticCorpus() []string {
	rng := rand.New(rand.NewSource(1))
	out := []string{
		"What is the weather forecast for Tuesday?",
		"Summarize the attached document in three bullets.",
		"List the top 5 customers by revenue this quarter.",
		"Translate the following paragraph into French.",
	}
	for i := 0; i < 30; i++ {
		out = append(out, fmt.Sprintf("Look up record %d %x and return the title.", i, rng.Int63()))
	}
	return out
}

// --- corpus mode ---

type Sample struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Label    string `json:"label"`
	Text     string `json:"text"`
	// Optional context: when set, the bench evaluates the sample as if
	// it appeared in this method/direction. Defaults to tools/call /
	// inbound. Used for method-scoped rules like tool-poisoning.
	Method    string `json:"method,omitempty"`
	Direction string `json:"direction,omitempty"`
	Field     string `json:"field,omitempty"`
}

func runCorpus(detectors []detect.Detector, path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("bench: open corpus: %v", err)
	}
	defer f.Close()

	type result struct {
		sample    Sample
		flagged   bool
		flaggedAs string
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	results := make([]result, 0, 1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var s Sample
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			log.Printf("skip malformed line: %v", err)
			continue
		}
		method := s.Method
		if method == "" {
			method = "tools/call"
		}
		dir := event.Direction(s.Direction)
		if dir == "" {
			dir = event.DirectionInbound
		}
		fieldName := s.Field
		if fieldName == "" {
			if dir == event.DirectionOutbound {
				fieldName = "result.text"
			} else {
				fieldName = "params.arguments.text"
			}
		}
		v := &detect.Verdict{}
		in := &detect.Input{
			Method:    method,
			Direction: dir,
			Fields:    []detect.Field{{Name: fieldName, Value: s.Text}},
		}
		for _, d := range detectors {
			_ = d.Detect(context.Background(), in, v)
		}
		flagged, cat := summarizeVerdict(v)
		results = append(results, result{sample: s, flagged: flagged, flaggedAs: cat})
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("bench: scan: %v", err)
	}

	// Compute per-category metrics.
	type metrics struct {
		tp, fp, fn, tn int
	}
	byCat := make(map[string]*metrics)
	overall := &metrics{}
	for _, r := range results {
		expectedMalicious := r.sample.Label == "malicious"
		expectedCat := r.sample.Category
		m := byCat[expectedCat]
		if m == nil {
			m = &metrics{}
			byCat[expectedCat] = m
		}
		switch {
		case expectedMalicious && r.flagged:
			m.tp++
			overall.tp++
		case expectedMalicious && !r.flagged:
			m.fn++
			overall.fn++
		case !expectedMalicious && r.flagged:
			m.fp++
			overall.fp++
		case !expectedMalicious && !r.flagged:
			m.tn++
			overall.tn++
		}
	}

	fmt.Printf("---- corpus benchmark (%s) ----\n", path)
	fmt.Printf("samples: %d\n", len(results))
	fmt.Println()

	categories := make([]string, 0, len(byCat))
	for c := range byCat {
		categories = append(categories, c)
	}
	sort.Strings(categories)
	fmt.Printf("%-26s %5s %5s %5s %5s   %6s %6s %6s\n", "category", "tp", "fp", "fn", "tn", "prec", "rec", "f1")
	for _, c := range categories {
		m := byCat[c]
		p, r, f1 := prRF(m.tp, m.fp, m.fn)
		fmt.Printf("%-26s %5d %5d %5d %5d   %6.3f %6.3f %6.3f\n",
			displayCategory(c), m.tp, m.fp, m.fn, m.tn, p, r, f1)
	}
	fmt.Println()
	p, r, f1 := prRF(overall.tp, overall.fp, overall.fn)
	fmt.Printf("OVERALL                   tp=%d fp=%d fn=%d tn=%d  P=%.3f R=%.3f F1=%.3f\n",
		overall.tp, overall.fp, overall.fn, overall.tn, p, r, f1)

	// Honest disclosure: list the misses so contributors know where
	// to focus. False positives are surprising flags on benign text;
	// false negatives are missed attacks.
	var fps, fns []result
	for _, res := range results {
		expectedMalicious := res.sample.Label == "malicious"
		switch {
		case !expectedMalicious && res.flagged:
			fps = append(fps, res)
		case expectedMalicious && !res.flagged:
			fns = append(fns, res)
		}
	}
	if len(fps) > 0 {
		fmt.Println("\nFALSE POSITIVES (benign text flagged):")
		for _, r := range fps {
			fmt.Printf("  %s [%s]: %s\n", r.sample.ID, r.flaggedAs, truncate(r.sample.Text, 100))
		}
	}
	if len(fns) > 0 {
		fmt.Println("\nFALSE NEGATIVES (malicious text missed):")
		for _, r := range fns {
			fmt.Printf("  %s [%s]: %s\n", r.sample.ID, r.sample.Category, truncate(r.sample.Text, 100))
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func summarizeVerdict(v *detect.Verdict) (bool, string) {
	if len(v.Findings) == 0 {
		return false, ""
	}
	return true, v.Findings[0].Category
}

func prRF(tp, fp, fn int) (precision, recall, f1 float64) {
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return
}

func displayCategory(c string) string {
	if c == "" {
		return "(benign)"
	}
	return c
}

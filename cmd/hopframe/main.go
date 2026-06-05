// Command hopframe is the operator CLI for a Hopframe control plane.
// It wraps the same /v1/* API the operator UI consumes, so any
// operation in the UI is reproducible from a shell script or CI step.
//
// Usage:
//
//	hopframe stats
//	hopframe verify
//	hopframe events list [--limit 50] [--action block]
//	hopframe events get <seq>
//	hopframe policies list
//	hopframe policies create -f policy.json
//	hopframe policies get <id>
//	hopframe policies preview <id>
//	hopframe policies delete <id>
//	hopframe sensors list
//	hopframe rules list [--category prompt-injection]
//	hopframe tokens mint --name X --role Y [--tenant Z]
//	hopframe tokens list
//	hopframe tokens revoke <id>
//	hopframe users add --username X --role Y
//	hopframe users list
//	hopframe users password <username>
//
// Configuration:
//
//	--server URL    or HOPFRAME_SERVER (default http://127.0.0.1:7090)
//	--token TOKEN   or HOPFRAME_API_TOKEN
//
// Output is JSON to stdout for programmatic use; pipe through `jq` for
// pretty rendering.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jlupsp/hopframe/internal/buildinfo"
)

// Set at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.MaybePrint("hopframe", version, commit, date)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Pull out --server and --token from anywhere in the arg list. They
	// can appear before or after the subcommand. After extraction the
	// remaining args are the subcommand and its flags.
	rawArgs := os.Args[1:]
	server := os.Getenv("HOPFRAME_SERVER")
	if server == "" {
		server = "http://127.0.0.1:7090"
	}
	token := os.Getenv("HOPFRAME_API_TOKEN")

	filtered := rawArgs[:0:len(rawArgs)]
	for i := 0; i < len(rawArgs); i++ {
		a := rawArgs[i]
		switch {
		case a == "--server":
			if i+1 >= len(rawArgs) {
				fmt.Fprintln(os.Stderr, "--server requires a value")
				os.Exit(2)
			}
			server = rawArgs[i+1]
			i++
		case strings.HasPrefix(a, "--server="):
			server = strings.TrimPrefix(a, "--server=")
		case a == "--token":
			if i+1 >= len(rawArgs) {
				fmt.Fprintln(os.Stderr, "--token requires a value")
				os.Exit(2)
			}
			token = rawArgs[i+1]
			i++
		case strings.HasPrefix(a, "--token="):
			token = strings.TrimPrefix(a, "--token=")
		default:
			filtered = append(filtered, a)
		}
	}
	if len(filtered) == 0 {
		usage()
		os.Exit(2)
	}
	cmd := filtered[0]
	args := filtered[1:]

	c := &client{server: strings.TrimRight(server, "/"), token: token}

	switch cmd {
	case "stats":
		mustOK(c.get("/v1/stats", nil))
	case "verify":
		mustOK(c.get("/v1/verify", nil))
	case "events":
		eventsCmd(c, args)
	case "policies":
		policiesCmd(c, args)
	case "sensors":
		sensorsCmd(c, args)
	case "rules":
		rulesCmd(c, args)
	case "tokens":
		tokensCmd(c, args)
	case "users":
		usersCmd(c, args)
	case "export":
		exportCmd(c, args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `hopframe, operator CLI for a Hopframe control plane

Usage:
  hopframe <command> [subcommand] [flags]

Common commands:
  stats                    chain head + seq + path
  verify                   re-walk the chain, report integrity
  events list              list recent events
  events get <seq>         fetch a record with signature + Merkle proof
  policies list            list policies
  policies create -f F.json create from file
  policies get <id>        fetch one
  policies preview <id>    dry-run the policy against recent events
  policies delete <id>
  sensors list             fleet inventory
  rules list               browse the loaded rule pack
  tokens mint --name X --role Y [--tenant Z]
  tokens list
  tokens revoke <id>
  users add --username X --role Y --password PASS
  users list
  users password <username>

Flags:
  --server URL             control plane (or HOPFRAME_SERVER)
  --token TOKEN            bearer token (or HOPFRAME_API_TOKEN)

Output is JSON to stdout. Pipe through jq for pretty rendering.`)
}

// ---------- subcommands ----------

func eventsCmd(c *client, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "events: expected list or get")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("events list", flag.ExitOnError)
		limit := fs.Int("limit", 50, "max events to return")
		action := fs.String("action", "", "filter by action: allow|warn|block")
		severity := fs.String("severity", "", "filter by severity")
		category := fs.String("category", "", "filter by category")
		method := fs.String("method", "", "filter by method")
		_ = fs.Parse(args[1:])
		q := url.Values{}
		q.Set("limit", fmt.Sprint(*limit))
		setIf(q, "action", *action)
		setIf(q, "severity", *severity)
		setIf(q, "category", *category)
		setIf(q, "method", *method)
		mustOK(c.get("/v1/events?"+q.Encode(), nil))
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "events get: <seq> required")
			os.Exit(2)
		}
		mustOK(c.get("/v1/records/"+args[1], nil))
	default:
		fmt.Fprintf(os.Stderr, "events: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func policiesCmd(c *client, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "policies: expected list|create|get|preview|delete")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		mustOK(c.get("/v1/policies", nil))
	case "create":
		fs := flag.NewFlagSet("policies create", flag.ExitOnError)
		file := fs.String("f", "", "JSON file with the policy body")
		_ = fs.Parse(args[1:])
		if *file == "" {
			fmt.Fprintln(os.Stderr, "policies create: -f FILE required")
			os.Exit(2)
		}
		body, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", *file, err)
			os.Exit(1)
		}
		mustOK(c.post("/v1/policies", body))
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "policies get: <id> required")
			os.Exit(2)
		}
		mustOK(c.get("/v1/policies/"+args[1], nil))
	case "preview":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "policies preview: <id> required")
			os.Exit(2)
		}
		mustOK(c.post("/v1/policies/"+args[1]+"/preview", []byte(`{}`)))
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "policies delete: <id> required")
			os.Exit(2)
		}
		mustOK(c.delete("/v1/policies/" + args[1]))
	default:
		fmt.Fprintf(os.Stderr, "policies: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func sensorsCmd(c *client, args []string) {
	if len(args) == 0 || args[0] == "list" {
		mustOK(c.get("/v1/sensors", nil))
		return
	}
	fmt.Fprintf(os.Stderr, "sensors: unknown subcommand %q\n", args[0])
	os.Exit(2)
}

func rulesCmd(c *client, args []string) {
	if len(args) == 0 || args[0] == "list" {
		mustOK(c.get("/v1/rules", nil))
		return
	}
	fmt.Fprintf(os.Stderr, "rules: unknown subcommand %q\n", args[0])
	os.Exit(2)
}

func tokensCmd(c *client, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "tokens: expected mint|list|revoke")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		mustOK(c.get("/v1/tokens", nil))
	case "mint":
		fs := flag.NewFlagSet("tokens mint", flag.ExitOnError)
		name := fs.String("name", "", "human-readable name (required)")
		role := fs.String("role", "", "viewer|editor|admin|owner (required)")
		tenant := fs.String("tenant", "", "tenant id (optional)")
		_ = fs.Parse(args[1:])
		if *name == "" || *role == "" {
			fmt.Fprintln(os.Stderr, "tokens mint: --name and --role required")
			os.Exit(2)
		}
		body, _ := json.Marshal(map[string]string{
			"name":      *name,
			"role":      *role,
			"tenant_id": *tenant,
		})
		mustOK(c.post("/v1/tokens", body))
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "tokens revoke: <id> required")
			os.Exit(2)
		}
		mustOK(c.delete("/v1/tokens/" + args[1]))
	default:
		fmt.Fprintf(os.Stderr, "tokens: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func usersCmd(c *client, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "users: expected list|add|password")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		mustOK(c.get("/v1/users", nil))
	case "add":
		fs := flag.NewFlagSet("users add", flag.ExitOnError)
		username := fs.String("username", "", "username (required)")
		password := fs.String("password", "", "password (required, 8+ chars)")
		role := fs.String("role", "viewer", "viewer|editor|admin|owner")
		tenant := fs.String("tenant", "", "tenant id")
		_ = fs.Parse(args[1:])
		if *username == "" || *password == "" {
			fmt.Fprintln(os.Stderr, "users add: --username and --password required")
			os.Exit(2)
		}
		body, _ := json.Marshal(map[string]string{
			"username":  *username,
			"password":  *password,
			"role":      *role,
			"tenant_id": *tenant,
		})
		mustOK(c.post("/v1/users", body))
	case "password":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "users password: <username> required")
			os.Exit(2)
		}
		fs := flag.NewFlagSet("users password", flag.ExitOnError)
		password := fs.String("password", "", "new password")
		_ = fs.Parse(args[2:])
		if *password == "" {
			fmt.Fprintln(os.Stderr, "users password: --password required")
			os.Exit(2)
		}
		body, _ := json.Marshal(map[string]string{"password": *password})
		mustOK(c.post("/v1/users/"+args[1]+"/password", body))
	default:
		fmt.Fprintf(os.Stderr, "users: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func exportCmd(c *client, _ []string) {
	fmt.Fprintln(os.Stderr, "hopframe export: use the dedicated `hopframe-export` binary for forensic bundles")
	os.Exit(2)
	_ = c
}

// ---------- HTTP client ----------

type client struct {
	server string
	token  string
}

func (c *client) get(path string, _ map[string]string) ([]byte, error) {
	return c.do(http.MethodGet, path, nil)
}

func (c *client) post(path string, body []byte) ([]byte, error) {
	return c.do(http.MethodPost, path, body)
}

func (c *client) delete(path string) ([]byte, error) {
	return c.do(http.MethodDelete, path, nil)
}

func (c *client) do(method, path string, body []byte) ([]byte, error) {
	var br io.Reader
	if body != nil {
		br = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.server+path, br)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return out, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func mustOK(body []byte, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if len(body) > 0 {
			fmt.Fprintln(os.Stderr, string(body))
		}
		os.Exit(1)
	}
	// Try to pretty-print JSON; fall back to raw bytes if it's not.
	var v any
	if json.Unmarshal(body, &v) == nil {
		out, _ := json.MarshalIndent(v, "", "  ")
		_, _ = os.Stdout.Write(out)
		_, _ = os.Stdout.Write([]byte("\n"))
		return
	}
	_, _ = os.Stdout.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		_, _ = os.Stdout.Write([]byte("\n"))
	}
}

func setIf(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

var _ = errors.New

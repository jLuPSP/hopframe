# ext_authz end-to-end lab

A real [Envoy](https://www.envoyproxy.io/) running Hopframe as its
authorization check, in front of a stub MCP server. Run it to see the
`mcp-extauthz` surface block a live attack through an actual gateway.

```
client ──POST MCP──> Envoy ──"allow or block?"──> Hopframe (mcp-extauthz)
                       │  allowed
                       └──route──> MCP server (stub)
```

## Run it

```sh
docker compose up -d --build
./run-test.sh                  # sends three requests through Envoy on :9101
docker compose down -v --rmi local
```

## What you'll see

| Request | Result |
|---|---|
| Normal tool call | **allowed**: the MCP server answers (`200`) |
| Tool call carrying an AWS key | **blocked**: `403`, the server is never reached |
| `tools/list` with a poisoned description | **allowed through**: ext_authz only checks the request, not the reply |

That last row is the surface's known limit: ext_authz inspects requests, not
replies, so a poisoned response slips past it. The full gateway and inline
sensor (`mcp-gateway`, `mcp-sensor`) close that gap. See
[deploy docs](../../../docs/index.md).

To watch it happen, flip the stub to its poisoned catalog
(`command: ["--addr", ":8088", "--poisoned"]` on the `upstream` service) and
re-run the `tools/list` request.

## Ports

`9101` MCP entry · `9190` Envoy admin (`/clusters`, `/stats`).

Everything runs on an isolated Docker network with no local-network values
(service names only), and tears down by label:

```sh
docker ps -aq --filter label=com.jlu.lab=extauthz-e2e | xargs -r docker rm -f
```

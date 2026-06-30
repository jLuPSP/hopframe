# ext_authz end-to-end lab

A real [Envoy](https://www.envoyproxy.io/) calling Hopframe over the Envoy
**HTTP external-authorization** contract, in front of a stub MCP server. This
is the integration proof for the `mcp-extauthz` surface: not a unit test with
a fake gateway, an actual gateway making allow/deny calls into Hopframe.

```
client --POST MCP--> envoy --ext_authz(HTTP, body attached)--> hopframe-authz (mcp-extauthz)
                       |  (on 200 allow)
                       +--route--> upstream (stub-mcp-server)
```

## What it proves

| Case | Request | Expected | Why |
| --- | --- | --- | --- |
| 1 | benign `tools/call` | **200**, stub answers | pipeline allows, Envoy routes upstream |
| 2 | `tools/call` with a canonical AWS key | **403**, JSON-RPC blocked-by-policy | request-side detection + hard deny via ext_authz |
| 3 | `tools/list` | **200** | ext_authz is request-side: it allows the request and never sees the response, so a poisoned description would pass here. The documented blind spot, see [docs/surface-matrix.md](../../../docs/surface-matrix.md). |

Case 3 is the honest part. To make the blind spot concrete, run the stub with
a poisoned catalog (`command: ["--addr", ":8088", "--poisoned"]` on the
`upstream` service): the smuggled `<system>` directive in a tool description
sails through ext_authz untouched, exactly the response-side gap that the
native sensor / gateway (`mcp-sensor`, `mcp-gateway`) closes.

## Run it (local Docker)

```sh
docker compose up -d --build
./run-test.sh                       # or: ./run-test.sh http://localhost:9101
docker logs lab-extauthz-e2e-hopframe-authz   # every verdict, as JSON events
docker compose down -v --remove-orphans --rmi local
```

Host ports: `9101` MCP ingress, `9190` Envoy admin (`/clusters`, `/stats`).

## Teardown (leave nothing behind)

```sh
docker compose down -v --remove-orphans --rmi local
# safety net: sweep by label even if the compose file is gone
docker ps -aq        --filter label=com.jlu.lab=extauthz-e2e | xargs -r docker rm -f
docker network ls -q --filter label=com.jlu.lab=extauthz-e2e | xargs -r docker network rm
```

The lab carries no local-network values; every address is a Docker service
name on its own isolated `labnet`.

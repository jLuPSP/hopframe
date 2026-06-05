// Public entrypoint. Framework adapters live under separate sub-paths
// (./mcp, ./ai-sdk, ./langchainjs, ./mastra) so users only pay for the
// imports they need; the base layer here is dependency-free.

export { Hopframe } from "./client.js";
export type { HopframeClientOptions } from "./client.js";
export {
  newEvent,
  newEventID,
  newRunID,
  SCHEMA_VERSION,
} from "./types.js";
export type {
  Action,
  Direction,
  Finding,
  HopframeEvent,
  Message,
  NewEventOptions,
  Protocol,
  Severity,
} from "./types.js";

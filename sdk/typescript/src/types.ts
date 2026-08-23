// Wire-compatible event types. Mirrors pkg/event/event.go on the Go
// side and sdk/python/hopframe/client.py on the Python side. Three
// implementations of the same shape so events from any producer land
// on the same control-plane timeline.

export const SCHEMA_VERSION = "hopframe.event/v1";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Action = "allow" | "warn" | "block";
export type Direction = "inbound" | "outbound";
export type Protocol = "mcp" | "a2a" | "agent" | "behavior" | "control";

export interface Finding {
  rule_id: string;
  category: string;
  severity: Severity;
  description?: string;
  match?: string;
  field?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
}

export interface Message {
  id?: string;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: Record<string, unknown>;
  raw?: string;
}

export interface HopframeEvent {
  schema: string;
  event_id: string;
  timestamp: string;
  sensor_id: string;
  tenant_id?: string;
  agent_run_id?: string;
  counterparty?: string;
  protocol: Protocol;
  direction: Direction;
  source?: string;
  destination?: string;
  message: Message;
  findings: Finding[];
  action: Action;
  severity: Severity;
  latency_micros?: number;
}

export interface NewEventOptions {
  protocol?: Protocol;
  direction?: Direction;
  agent_run_id?: string;
  counterparty?: string;
  source?: string;
  destination?: string;
  message?: Message;
  findings?: Finding[];
  action?: Action;
  severity?: Severity;
  latency_micros?: number;
}

const HEX = "0123456789abcdef";

export function newEventID(): string {
  const buf = new Uint8Array(12);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  let out = "ev-";
  for (let i = 0; i < buf.length; i++) {
    out += HEX[buf[i] >> 4] + HEX[buf[i] & 0xf];
  }
  return out;
}

export function newRunID(): string {
  return "run-" + newEventID().slice(3);
}

export function newEvent(sensorID: string, opts: NewEventOptions = {}): HopframeEvent {
  return {
    schema: SCHEMA_VERSION,
    event_id: newEventID(),
    timestamp: new Date().toISOString(),
    sensor_id: sensorID,
    agent_run_id: opts.agent_run_id,
    counterparty: opts.counterparty,
    protocol: opts.protocol ?? "agent",
    direction: opts.direction ?? "inbound",
    source: opts.source,
    destination: opts.destination,
    message: opts.message ?? {},
    findings: opts.findings ?? [],
    action: opts.action ?? "allow",
    severity: opts.severity ?? "info",
    ...(opts.latency_micros === undefined ? {} : { latency_micros: opts.latency_micros }),
  };
}

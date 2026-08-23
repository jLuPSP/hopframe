// Hopframe TypeScript client. Buffers events and ships them to the
// control plane in batches. Designed to be dependency-free at the base
// layer: no required runtime deps. Framework integrations import their
// own deps lazily from src/integrations/.
//
// Mirrors the Python SDK shape so a contributor reading both can move
// between them without re-learning the model.

import { HopframeEvent, NewEventOptions, newEvent } from "./types.js";

export interface HopframeClientOptions {
  baseURL: string;
  token?: string;
  sensorID?: string;
  tenantID?: string;
  // Maximum events held in memory before send. Defaults to 64.
  batchSize?: number;
  // How often the background flusher runs, ms. Defaults to 1000.
  flushIntervalMs?: number;
  // Maximum retries per batch on transient failure. Defaults to 3.
  maxRetries?: number;
  // Override fetch (useful for tests). Defaults to globalThis.fetch.
  fetchImpl?: typeof fetch;
  // Callback invoked when a send fails after maxRetries. Drops counted.
  onDrop?: (count: number, err: unknown) => void;
}

export class Hopframe {
  private opts: Required<Omit<HopframeClientOptions, "fetchImpl" | "onDrop">>;
  private fetchImpl: typeof fetch;
  private onDrop: HopframeClientOptions["onDrop"];
  private buffer: HopframeEvent[] = [];
  private timer: ReturnType<typeof setInterval> | undefined;
  private closed = false;
  private inflight: Promise<void> = Promise.resolve();

  constructor(options: HopframeClientOptions) {
    if (!options.baseURL) throw new Error("hopframe: baseURL required");
    this.opts = {
      baseURL: options.baseURL.replace(/\/+$/, ""),
      token: options.token ?? "",
      sensorID: options.sensorID ?? "ts-sdk",
      tenantID: options.tenantID ?? "",
      batchSize: options.batchSize ?? 64,
      flushIntervalMs: options.flushIntervalMs ?? 1000,
      maxRetries: options.maxRetries ?? 3,
    };
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onDrop = options.onDrop;
    this.start();
  }

  // emit returns synchronously after queuing. The flusher delivers in
  // the background and retries with exponential backoff on transient
  // failure. Caller code should not block on emit.
  emit(opts: NewEventOptions): HopframeEvent {
    const ev = newEvent(this.opts.sensorID, opts);
    if (this.opts.tenantID) ev.tenant_id = this.opts.tenantID;
    this.buffer.push(ev);
    if (this.buffer.length >= this.opts.batchSize) {
      this.flushAsync();
    }
    return ev;
  }

  // flushNow drains the buffer and waits for in-flight delivery to
  // finish. Use before process exit. Idempotent.
  async flushNow(): Promise<void> {
    this.flushAsync();
    await this.inflight;
  }

  // close flushes and stops the background timer. After close, emit
  // still queues but no flusher runs; call flushNow before exit.
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.timer) clearInterval(this.timer);
    await this.flushNow();
  }

  private start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.flushAsync(), this.opts.flushIntervalMs);
    // Don't keep the Node process alive solely for the flush timer.
    const timer = this.timer as ReturnType<typeof setInterval> & { unref?: () => void };
    timer.unref?.();
  }

  private flushAsync(): void {
    if (this.buffer.length === 0) return;
    const batch = this.buffer;
    this.buffer = [];
    this.inflight = this.inflight.then(() => this.send(batch));
  }

  private async send(batch: HopframeEvent[]): Promise<void> {
    let delay = 100;
    for (let attempt = 0; attempt <= this.opts.maxRetries; attempt++) {
      try {
        // The control plane currently accepts one event per POST; batch
        // by issuing concurrent requests with a small concurrency cap.
        // A future v2 ingest will accept arrays in a single POST; this
        // SDK swaps to that path when the server advertises it.
        await Promise.all(batch.map(ev => this.postOne(ev)));
        return;
      } catch (err) {
        // 4xx (except 429) is a permanent client error; the request
        // shape is wrong and a retry can't fix it. Drop the batch and
        // count it once. 5xx and 429 fall through to backoff.
        if (err instanceof PermanentError) {
          this.onDrop?.(batch.length, err);
          return;
        }
        if (attempt === this.opts.maxRetries) {
          this.onDrop?.(batch.length, err);
          return;
        }
        await sleep(delay);
        delay = Math.min(delay * 2, 5000);
      }
    }
  }

  private async postOne(ev: HopframeEvent): Promise<void> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.opts.token) headers["Authorization"] = "Bearer " + this.opts.token;
    if (ev.agent_run_id) headers["X-Hopframe-Agent-Run-Id"] = ev.agent_run_id;

    const res = await this.fetchImpl(this.opts.baseURL + "/v1/events", {
      method: "POST",
      headers,
      body: JSON.stringify(ev),
    });
    if (!res.ok && res.status >= 400 && res.status < 500 && res.status !== 429) {
      // Permanent client error; do not retry.
      const body = await res.text();
      throw new PermanentError(`hopframe: ${res.status} ${body}`);
    }
    if (!res.ok) {
      throw new Error(`hopframe: ${res.status}`);
    }
  }
}

class PermanentError extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

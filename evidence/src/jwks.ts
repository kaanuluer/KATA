// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// JWKS fetch and TTL cache. Only Ed25519 and P-256 public keys are kept.

import { createHash } from "node:crypto";
import type { EvidenceStore, CachedKey } from "./store.ts";
import { DirectoryRejected, ResolveFailed, assertPublicHttps, type Resolve } from "./ssrf.ts";

export const DEFAULT_TTL_SECONDS = 300;
export const DEFAULT_MAX_ENTRIES = 64;
export const DEFAULT_MAX_KEYS = 8;
export const DEFAULT_MAX_BYTES = 65536;
export const DEFAULT_TIMEOUT_SECONDS = 2;

export class FetchFailed extends Error {
  constructor() {
    super("jwks fetch failed");
  }
}

export class JwksRejected extends Error {
  constructor() {
    super("jwks document was refused");
  }
}

export type Fetch = (url: string, timeoutSeconds: number) => Promise<Uint8Array> | Uint8Array;

export function directoryHash(url: string): string {
  const parsed = new URL(url);
  const path = parsed.pathname || "/";
  const normalized = `${parsed.protocol}//${parsed.host.toLowerCase()}${path}${parsed.search}`;
  return createHash("sha256").update(normalized).digest("hex");
}

function algorithmOf(jwk: Record<string, unknown>): "EdDSA" | "ES256" | null {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  return null;
}

export function publicJwk(value: unknown): CachedKey & { alg: "EdDSA" | "ES256" } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const jwk = value as Record<string, unknown>;
  if ("d" in jwk) return null;
  const algorithm = algorithmOf(jwk);
  if (!algorithm) return null;
  if (jwk.alg !== undefined && jwk.alg !== algorithm) return null;
  if (jwk.use !== undefined && jwk.use !== "sig") return null;
  if (jwk.key_ops !== undefined && JSON.stringify(jwk.key_ops) !== JSON.stringify(["verify"])) return null;
  if (typeof jwk.kid !== "string" || !jwk.kid || jwk.kid.length > 200) return null;
  if (typeof jwk.x !== "string" || !jwk.x) return null;
  const stored: Record<string, unknown> = {
    alg: algorithm,
    crv: algorithm === "EdDSA" ? "Ed25519" : "P-256",
    kid: jwk.kid,
    kty: algorithm === "EdDSA" ? "OKP" : "EC",
    use: "sig",
    x: jwk.x,
  };
  if (algorithm === "ES256") {
    if (typeof jwk.y !== "string" || !jwk.y) return null;
    stored.y = jwk.y;
  }
  return { kid: jwk.kid, alg: algorithm, jwk: stored };
}

export function parseJwks(body: Uint8Array, maxKeys: number): CachedKey[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    throw new FetchFailed();
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { keys?: unknown }).keys)) throw new JwksRejected();
  const members = (parsed as { keys: unknown[] }).keys;
  if (members.length > maxKeys) throw new JwksRejected();
  const usable = members.map(publicJwk).filter((item): item is NonNullable<typeof item> => item !== null);
  if (!usable.length) throw new JwksRejected();
  return usable.map((item) => ({ kid: item.kid, jwk: item.jwk }));
}

export class KeyCache {
  readonly maxEntries: number;
  readonly maxBytes: number;
  private readonly store: EvidenceStore;
  private readonly fetchImpl: Fetch;
  private readonly resolve: Resolve;
  private readonly ttlSeconds: number;
  private readonly maxKeys: number;
  private readonly timeout: number;

  constructor(
    store: EvidenceStore,
    fetchImpl: Fetch,
    resolve: Resolve,
    ttlSeconds = DEFAULT_TTL_SECONDS,
    maxEntries = DEFAULT_MAX_ENTRIES,
    maxKeys = DEFAULT_MAX_KEYS,
    maxBytes = DEFAULT_MAX_BYTES,
    timeout = DEFAULT_TIMEOUT_SECONDS,
  ) {
    this.store = store;
    this.fetchImpl = fetchImpl;
    this.resolve = resolve;
    this.ttlSeconds = ttlSeconds;
    this.maxEntries = maxEntries;
    this.maxKeys = maxKeys;
    this.maxBytes = maxBytes;
    this.timeout = timeout;
  }

  async keysFor(directory: string, kid: string, now: Date): Promise<CachedKey[]> {
    try {
      await assertPublicHttps(directory, this.resolve);
    } catch (error) {
      if (error instanceof ResolveFailed) throw new FetchFailed();
      throw error;
    }
    const digest = directoryHash(directory);
    const cached = await this.store.readKeys(digest, now);
    if (cached.some((item) => item.kid === kid)) return cached;
    return this.refresh(directory, digest, now);
  }

  private async refresh(directory: string, digest: string, now: Date): Promise<CachedKey[]> {
    let body: Uint8Array;
    try {
      body = await this.fetchImpl(directory, this.timeout);
    } catch (error) {
      if (error instanceof FetchFailed) throw error;
      throw new FetchFailed();
    }
    if (body.byteLength > this.maxBytes) throw new FetchFailed();
    const keys = parseJwks(body, this.maxKeys);
    const expires = new Date(now.getTime() + this.ttlSeconds * 1000);
    await this.store.putKeys(digest, keys, now, expires, this.maxEntries);
    return this.store.readKeys(digest, now);
  }
}

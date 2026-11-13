// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Pluggable evidence verifiers. jwt uses jose. synthetic is the test verifier.
// Neither returns a KATA decision.

import { errors, importJWK, jwtVerify } from "jose";
import {
  CLOCK_SKEW_SECONDS,
  emptyHash,
  evidenceObject,
  payloadHash,
  sanitizeClaims,
  type Evidence,
} from "./schema.ts";
import { FetchFailed, JwksRejected, KeyCache, type Fetch } from "./jwks.ts";
import { DirectoryRejected, type Resolve } from "./ssrf.ts";
import type { EvidenceStore } from "./store.ts";

const ALLOWED = new Set(["EdDSA", "ES256"]);
const SKEW_MS = CLOCK_SKEW_SECONDS * 1000;

export interface EvidenceMaterial {
  [key: string]: unknown;
}

export interface EvidenceVerifier {
  readonly source: string;
  verify(material: EvidenceMaterial, now: Date): Promise<Evidence>;
}

export interface VerifierDeps {
  fetch?: Fetch;
  resolve?: Resolve;
  ttlSeconds?: number;
  maxEntries?: number;
  maxKeys?: number;
  maxBytes?: number;
  timeout?: number;
}

type Builder = (store: EvidenceStore, deps: VerifierDeps) => EvidenceVerifier;

const builders = new Map<string, Builder>();

export function registerVerifier(source: string, builder: Builder): void {
  builders.set(source, builder);
}

export function verifierFor(source: string, store: EvidenceStore, deps: VerifierDeps = {}): EvidenceVerifier {
  const builder = builders.get(source);
  if (!builder) return new UnsupportedVerifier(source);
  return builder(store, deps);
}

export function evidenceVerifierEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.GAB_EVIDENCE_VERIFIER ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function stamp(now: Date): string {
  return new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function text(value: unknown, limit: number): string {
  return typeof value === "string" && value.length <= limit ? value : "";
}

function b64urlDecode(segment: string): Buffer | null {
  if (!segment || !/^[\w-]+$/.test(segment)) return null;
  try {
    const decoded = Buffer.from(segment, "base64url");
    return decoded.length ? decoded : null;
  } catch {
    return null;
  }
}

function numericDate(value: unknown): Date | null {
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  if (value < 0 || value > 10_000_000_000) return null;
  return new Date(value * 1000);
}

function invalid(source: string, now: Date, reason: string, digest: string, keyId = ""): Evidence {
  const unverifiable = reason === "jwks_fetch_failed" || reason === "jwks_rejected" || reason === "directory_url_rejected";
  return evidenceObject({
    source,
    verified_at: stamp(now),
    key_id: keyId,
    result: unverifiable ? "unverifiable" : "invalid",
    reason,
    payload_hash: digest,
  });
}

class UnsupportedVerifier implements EvidenceVerifier {
  readonly source: string;
  constructor(source: string) {
    this.source = source.length >= 1 && source.length <= 64 ? source : "unknown";
  }
  async verify(_material: EvidenceMaterial, now: Date): Promise<Evidence> {
    return evidenceObject({
      source: this.source,
      verified_at: stamp(now),
      result: "unverifiable",
      reason: "unsupported_verifier",
      payload_hash: emptyHash(),
    });
  }
}

class SyntheticVerifier implements EvidenceVerifier {
  readonly source = "synthetic";
  private readonly store: EvidenceStore;
  constructor(store: EvidenceStore) {
    this.store = store;
  }

  async verify(material: EvidenceMaterial, now: Date): Promise<Evidence> {
    const moment = new Date(Math.floor(now.getTime() / 1000) * 1000);
    const rawClaims = material.claims && typeof material.claims === "object" ? (material.claims as Record<string, unknown>) : {};
    const sanitized = sanitizeClaims(rawClaims);
    const digest = payloadHash(Buffer.from(JSON.stringify(sanitized.claims)));
    const issuer = text(material.issuer, 200);
    const subject = text(material.subject, 200);
    const keyId = text(material.key_id, 200);
    if (sanitized.reason) {
      return evidenceObject({
        source: this.source,
        issuer,
        subject,
        verified_at: stamp(moment),
        key_id: keyId,
        result: "invalid",
        reason: "sensitive_claim",
        payload_hash: digest,
      });
    }
    if (material.accept !== true) {
      return evidenceObject({
        source: this.source,
        issuer,
        subject,
        claims: sanitized.claims,
        verified_at: stamp(moment),
        key_id: keyId,
        result: "invalid",
        reason: "signature",
        payload_hash: digest,
      });
    }
    const nonce = material.nonce;
    if (typeof nonce !== "string" || !nonce || nonce.length > 200 || !issuer || !subject || !keyId) {
      return evidenceObject({
        source: this.source,
        issuer,
        subject,
        claims: sanitized.claims,
        verified_at: stamp(moment),
        key_id: keyId,
        result: "invalid",
        reason: issuer && subject && keyId ? "nonce_missing" : "malformed",
        payload_hash: digest,
      });
    }
    const ttl = typeof material.ttl_seconds === "number" && material.ttl_seconds > 0 ? material.ttl_seconds : 300;
    const fresh = await this.store.consumeNonce(issuer, nonce, moment, new Date(moment.getTime() + ttl * 1000));
    return evidenceObject({
      source: this.source,
      issuer,
      subject,
      claims: sanitized.claims,
      verified_at: stamp(moment),
      key_id: keyId,
      result: fresh ? "valid" : "invalid",
      reason: fresh ? "ok" : "replay",
      payload_hash: digest,
    });
  }
}

class JwtEvidenceVerifier implements EvidenceVerifier {
  readonly source = "jwt";
  private readonly cache: KeyCache;
  private readonly store: EvidenceStore;

  constructor(store: EvidenceStore, deps: VerifierDeps) {
    this.store = store;
    this.cache = new KeyCache(
      store,
      deps.fetch ?? (async () => {
        throw new FetchFailed();
      }),
      deps.resolve ?? (async () => ["8.8.8.8"]),
      deps.ttlSeconds ?? 300,
      deps.maxEntries ?? 64,
      deps.maxKeys ?? 8,
      deps.maxBytes ?? 65536,
      deps.timeout ?? 2,
    );
  }

  async verify(material: EvidenceMaterial, now: Date): Promise<Evidence> {
    const moment = new Date(Math.floor(now.getTime() / 1000) * 1000);
    const token = material.token;
    if (typeof token !== "string") return invalid(this.source, moment, "malformed", emptyHash());
    const parts = token.split(".");
    if (parts.length !== 3) return invalid(this.source, moment, "malformed", emptyHash());
    if (![...parts[0]].every((char) => char.charCodeAt(0) < 128) || ![...parts[1]].every((char) => char.charCodeAt(0) < 128)) {
      return invalid(this.source, moment, "malformed", emptyHash());
    }
    const headerBytes = b64urlDecode(parts[0]);
    const payloadBytes = b64urlDecode(parts[1]);
    const digest = payloadHash(payloadBytes ?? Buffer.alloc(0));
    if (!headerBytes || !payloadBytes) return invalid(this.source, moment, "malformed", digest);
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(headerBytes.toString("utf8"));
    } catch {
      return invalid(this.source, moment, "malformed", digest);
    }
    if (!header || typeof header !== "object" || Array.isArray(header)) return invalid(this.source, moment, "malformed", digest);
    const algorithm = header.alg;
    if (typeof algorithm !== "string" || !ALLOWED.has(algorithm)) return invalid(this.source, moment, "alg_rejected", digest);
    const signature = parts[2] ? b64urlDecode(parts[2]) : Buffer.alloc(0);
    if (signature === null) return invalid(this.source, moment, "malformed", digest);
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(payloadBytes.toString("utf8"));
    } catch {
      return invalid(this.source, moment, "malformed", digest);
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return invalid(this.source, moment, "malformed", digest);
    if ("crit" in header) return invalid(this.source, moment, "malformed", digest);
    const kid = header.kid;
    if (typeof kid !== "string" || !kid) return invalid(this.source, moment, "unknown_kid", digest);
    const timed = timeProblem(payload, moment);
    if (timed) return fromPayload(moment, payload, digest, "invalid", timed, kid);
    const sanitized = sanitizeClaims(payload);
    if (sanitized.reason) return invalid(this.source, moment, "sensitive_claim", digest, kid);
    const directory = material.directory;
    if (typeof directory !== "string") return fromPayload(moment, payload, digest, "unverifiable", "directory_url_rejected", kid);
    let keys;
    try {
      keys = await this.cache.keysFor(directory, kid, moment);
    } catch (error) {
      if (error instanceof DirectoryRejected) return fromPayload(moment, payload, digest, "unverifiable", "directory_url_rejected", kid);
      if (error instanceof JwksRejected) return fromPayload(moment, payload, digest, "unverifiable", "jwks_rejected", kid);
      return fromPayload(moment, payload, digest, "unverifiable", "jwks_fetch_failed", kid);
    }
    const chosen = keys.find((item) => item.kid === kid);
    if (!chosen) return fromPayload(moment, payload, digest, "invalid", "unknown_kid", kid);
    if (chosen.jwk.alg !== algorithm) return fromPayload(moment, payload, digest, "invalid", "alg_mismatch", kid);
    try {
      const key = await importJWK(chosen.jwk, algorithm);
      await jwtVerify(token, key, { algorithms: [algorithm], clockTolerance: CLOCK_SKEW_SECONDS, currentDate: moment });
    } catch (error) {
      const timeClaim = error instanceof errors.JWTExpired || error instanceof errors.JWTClaimValidationFailed;
      if (!timeClaim) return fromPayload(moment, payload, digest, "invalid", "signature", kid);
    }
    const issuer = payload.iss;
    const subject = payload.sub;
    if (typeof issuer !== "string" || !issuer || issuer.length > 200) return fromPayload(moment, payload, digest, "invalid", "malformed", kid);
    if (typeof subject !== "string" || !subject || subject.length > 200) return fromPayload(moment, payload, digest, "invalid", "malformed", kid);
    const nonce = payload.jti;
    if (typeof nonce !== "string" || !nonce || nonce.length > 200) return fromPayload(moment, payload, digest, "invalid", "nonce_missing", kid);
    const exp = numericDate(payload.exp);
    if (!exp) return fromPayload(moment, payload, digest, "invalid", "malformed", kid);
    const fresh = await this.store.consumeNonce(issuer, nonce, moment, new Date(exp.getTime() + SKEW_MS));
    return evidenceObject({
      source: this.source,
      issuer,
      subject,
      claims: sanitizeClaims(payload).claims,
      verified_at: stamp(moment),
      key_id: kid,
      result: fresh ? "valid" : "invalid",
      reason: fresh ? "ok" : "replay",
      payload_hash: digest,
    });
  }
}

function timeProblem(payload: Record<string, unknown>, now: Date): string | null {
  const exp = numericDate(payload.exp);
  if (!exp) return "malformed";
  if (exp.getTime() < now.getTime() - SKEW_MS) return "expired";
  if (payload.nbf !== undefined) {
    const notBefore = numericDate(payload.nbf);
    if (!notBefore) return "malformed";
    if (notBefore.getTime() > now.getTime() + SKEW_MS) return "not_yet_valid";
  }
  if (payload.iat !== undefined) {
    const issued = numericDate(payload.iat);
    if (!issued) return "malformed";
    if (issued.getTime() > now.getTime() + SKEW_MS) return "future_iat";
  }
  return null;
}

function fromPayload(now: Date, payload: Record<string, unknown>, digest: string, result: "valid" | "invalid" | "unverifiable", reason: string, kid: string): Evidence {
  const sanitized = sanitizeClaims(payload);
  let claims = sanitized.claims;
  let nextResult = result;
  let nextReason = reason;
  if (sanitized.reason) {
    claims = {};
    if (nextResult === "valid") {
      nextResult = "invalid";
      nextReason = "sensitive_claim";
    }
  }
  return evidenceObject({
    source: "jwt",
    issuer: typeof payload.iss === "string" && payload.iss.length <= 200 ? payload.iss : "",
    subject: typeof payload.sub === "string" && payload.sub.length <= 200 ? payload.sub : "",
    claims,
    verified_at: stamp(now),
    key_id: kid.length <= 200 ? kid : "",
    result: nextResult,
    reason: nextReason,
    payload_hash: digest,
  });
}

registerVerifier("synthetic", (store) => new SyntheticVerifier(store));
registerVerifier("jwt", (store, deps) => new JwtEvidenceVerifier(store, deps));

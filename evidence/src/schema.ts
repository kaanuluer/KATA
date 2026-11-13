// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Evidence returned by every verifier. result is not a KATA decision.

import { createHash } from "node:crypto";
import { z } from "zod";

export const CLOCK_SKEW_SECONDS = 60;

export const evidenceResultSchema = z.enum(["valid", "invalid", "unverifiable"]);

const scalarClaim = z.union([z.string().max(200), z.number().finite(), z.boolean(), z.null()]);

export const evidenceSchema = z
  .object({
    source: z.string().min(1).max(64),
    issuer: z.string().max(200),
    subject: z.string().max(200),
    claims: z.record(z.string().max(64), scalarClaim).refine((claims) => Object.keys(claims).length <= 16),
    verified_at: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/),
    key_id: z.string().max(200),
    result: evidenceResultSchema,
    reason: z.string().min(1).max(80),
    payload_hash: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

export type Evidence = z.infer<typeof evidenceSchema>;
export type EvidenceResult = z.infer<typeof evidenceResultSchema>;

export const SENSITIVE_CLAIM_NAMES = new Set([
  "aadhaar",
  "driver_license",
  "drivers_license",
  "government_id",
  "itin",
  "national_id",
  "nino",
  "passport",
  "passport_number",
  "sin",
  "social_security",
  "ssn",
  "tax_id",
]);

export function payloadHash(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function emptyHash(): string {
  return payloadHash(Buffer.alloc(0));
}

export type ClaimValue = string | number | boolean | null;

export function sanitizeClaims(payload: Record<string, unknown>): { claims: Record<string, ClaimValue>; reason: string | null } {
  const names = new Set(Object.keys(payload).map((key) => key.toLowerCase()));
  for (const name of names) {
    if (SENSITIVE_CLAIM_NAMES.has(name)) return { claims: {}, reason: "sensitive_claim" };
  }
  const claims: Record<string, ClaimValue> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (Object.keys(claims).length >= 16) break;
    if (!key || key.length > 64) continue;
    if (typeof value === "string") {
      if (value.length <= 200) claims[key] = value;
      continue;
    }
    if (typeof value === "boolean" || value === null) {
      claims[key] = value;
      continue;
    }
    if (typeof value === "number" && Number.isFinite(value)) claims[key] = value;
  }
  return { claims, reason: null };
}

export function evidenceObject(input: {
  source: string;
  verified_at: string;
  result: EvidenceResult;
  reason: string;
  payload_hash: string;
  issuer?: string;
  subject?: string;
  claims?: Record<string, ClaimValue>;
  key_id?: string;
}): Evidence {
  return evidenceSchema.parse({
    source: input.source,
    issuer: input.issuer ?? "",
    subject: input.subject ?? "",
    claims: input.claims ?? {},
    verified_at: input.verified_at,
    key_id: input.key_id ?? "",
    result: input.result,
    reason: input.reason,
    payload_hash: input.payload_hash,
  });
}

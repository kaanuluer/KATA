// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Key cache, nonce window, and evidence rows. Postgres or memory. No Redis.

import pg from "pg";
import { evidenceSchema, type Evidence } from "./schema.ts";

export interface CachedKey {
  kid: string;
  jwk: Record<string, unknown>;
}

export interface EvidenceRecord {
  evidence_id: string;
  evidence: Evidence;
  decision_ref: string;
  agent_id: string | null;
  agreement_id: string | null;
  action_id: string | null;
  kata_decision: string | null;
  audit_id: string | null;
  created_at: string;
}

export interface EvidenceStore {
  readKeys(directoryHash: string, now: Date): Promise<CachedKey[]>;
  putKeys(directoryHash: string, keys: CachedKey[], now: Date, expiresAt: Date, maxEntries: number): Promise<void>;
  consumeNonce(issuer: string, nonce: string, now: Date, expiresAt: Date): Promise<boolean>;
  saveEvidence(record: EvidenceRecord): Promise<void>;
  listEvidence(decisionRef?: string): Promise<EvidenceRecord[]>;
  linkAudit(evidenceId: string, auditId: string): Promise<void>;
}

function stamp(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export class MemoryEvidenceStore implements EvidenceStore {
  private keys: Array<CachedKey & { directoryHash: string; fetchedAt: Date; expiresAt: Date }> = [];
  private nonces = new Map<string, Date>();
  private evidence: EvidenceRecord[] = [];

  async readKeys(directoryHash: string, now: Date): Promise<CachedKey[]> {
    return this.keys
      .filter((item) => item.directoryHash === directoryHash && item.expiresAt.getTime() > now.getTime())
      .map((item) => ({ kid: item.kid, jwk: { ...item.jwk } }));
  }

  async putKeys(directoryHash: string, keys: CachedKey[], now: Date, expiresAt: Date, maxEntries: number): Promise<void> {
    this.keys = this.keys.filter((item) => item.directoryHash !== directoryHash);
    for (const key of keys) {
      this.keys.push({ directoryHash, kid: key.kid, jwk: { ...key.jwk }, fetchedAt: now, expiresAt });
    }
    if (this.keys.length > maxEntries) {
      this.keys.sort((left, right) => {
        const time = left.fetchedAt.getTime() - right.fetchedAt.getTime();
        if (time !== 0) return time;
        return `${left.directoryHash}:${left.kid}`.localeCompare(`${right.directoryHash}:${right.kid}`);
      });
      this.keys = this.keys.slice(-maxEntries);
    }
  }

  async consumeNonce(issuer: string, nonce: string, now: Date, expiresAt: Date): Promise<boolean> {
    for (const [key, expiry] of this.nonces) {
      if (expiry.getTime() <= now.getTime()) this.nonces.delete(key);
    }
    const key = `${issuer}\n${nonce}`;
    if (this.nonces.has(key)) return false;
    this.nonces.set(key, expiresAt);
    return true;
  }

  async saveEvidence(record: EvidenceRecord): Promise<void> {
    evidenceSchema.parse(record.evidence);
    this.evidence.push(structuredClone(record));
  }

  async listEvidence(decisionRef?: string): Promise<EvidenceRecord[]> {
    const rows = decisionRef === undefined ? this.evidence : this.evidence.filter((item) => item.decision_ref === decisionRef);
    return structuredClone(rows);
  }

  async linkAudit(evidenceId: string, auditId: string): Promise<void> {
    const row = this.evidence.find((item) => item.evidence_id === evidenceId);
    if (row) row.audit_id = auditId;
  }
}

export class PostgresEvidenceStore implements EvidenceStore {
  private readonly databaseUrl: string;
  private readonly schema: string;

  constructor(databaseUrl: string, schema = "public") {
    if (!/^[a-z_][a-z0-9_]*$/.test(schema)) throw new Error("schema name is not allowed");
    this.databaseUrl = databaseUrl;
    this.schema = schema;
  }

  private async withClient<T>(run: (client: pg.Client) => Promise<T>): Promise<T> {
    const client = new pg.Client({ connectionString: this.databaseUrl });
    await client.connect();
    try {
      await client.query(`SET search_path TO ${this.schema}`);
      return await run(client);
    } finally {
      await client.end();
    }
  }

  async readKeys(directoryHash: string, now: Date): Promise<CachedKey[]> {
    return this.withClient(async (client) => {
      const result = await client.query(
        "SELECT kid, public_jwk FROM gab_evidence_keys WHERE directory_hash = $1 AND expires_at > $2",
        [directoryHash, stamp(now)],
      );
      return result.rows.map((row) => ({ kid: row.kid as string, jwk: JSON.parse(row.public_jwk as string) }));
    });
  }

  async putKeys(directoryHash: string, keys: CachedKey[], now: Date, expiresAt: Date, maxEntries: number): Promise<void> {
    await this.withClient(async (client) => {
      await client.query("BEGIN");
      await client.query("DELETE FROM gab_evidence_keys WHERE directory_hash = $1", [directoryHash]);
      for (const key of keys) {
        await client.query(
          `INSERT INTO gab_evidence_keys (directory_hash, kid, public_jwk, fetched_at, expires_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [directoryHash, key.kid, JSON.stringify(key.jwk), stamp(now), stamp(expiresAt)],
        );
      }
      await client.query(
        `DELETE FROM gab_evidence_keys
         WHERE (directory_hash, kid) IN (
           SELECT directory_hash, kid FROM gab_evidence_keys
           ORDER BY fetched_at DESC, directory_hash DESC, kid DESC
           OFFSET $1
         )`,
        [maxEntries],
      );
      await client.query("COMMIT");
    });
  }

  async consumeNonce(issuer: string, nonce: string, now: Date, expiresAt: Date): Promise<boolean> {
    return this.withClient(async (client) => {
      await client.query("BEGIN");
      await client.query("DELETE FROM gab_evidence_nonces WHERE expires_at <= $1", [stamp(now)]);
      const inserted = await client.query(
        `INSERT INTO gab_evidence_nonces (issuer, nonce, seen_at, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (issuer, nonce) DO NOTHING
         RETURNING issuer`,
        [issuer, nonce, stamp(now), stamp(expiresAt)],
      );
      await client.query("COMMIT");
      return inserted.rowCount === 1;
    });
  }

  async saveEvidence(record: EvidenceRecord): Promise<void> {
    const evidence = evidenceSchema.parse(record.evidence);
    await this.withClient(async (client) => {
      await client.query(
        `INSERT INTO gab_external_evidence (
           evidence_id, source, issuer, subject, claims, verified_at, key_id, result, reason,
           payload_hash, decision_ref, agent_id, agreement_id, action_id, kata_decision, audit_id, created_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [
          record.evidence_id,
          evidence.source,
          evidence.issuer,
          evidence.subject,
          JSON.stringify(evidence.claims),
          evidence.verified_at,
          evidence.key_id,
          evidence.result,
          evidence.reason,
          evidence.payload_hash,
          record.decision_ref,
          record.agent_id,
          record.agreement_id,
          record.action_id,
          record.kata_decision,
          record.audit_id,
          record.created_at,
        ],
      );
    });
  }

  async listEvidence(decisionRef?: string): Promise<EvidenceRecord[]> {
    return this.withClient(async (client) => {
      const result =
        decisionRef === undefined
          ? await client.query(
              `SELECT evidence_id, source, issuer, subject, claims, verified_at, key_id, result, reason,
                      payload_hash, decision_ref, agent_id, agreement_id, action_id, kata_decision, audit_id, created_at
               FROM gab_external_evidence ORDER BY created_at, evidence_id`,
            )
          : await client.query(
              `SELECT evidence_id, source, issuer, subject, claims, verified_at, key_id, result, reason,
                      payload_hash, decision_ref, agent_id, agreement_id, action_id, kata_decision, audit_id, created_at
               FROM gab_external_evidence WHERE decision_ref = $1 ORDER BY created_at, evidence_id`,
              [decisionRef],
            );
      return result.rows.map((row) => ({
        evidence_id: row.evidence_id,
        evidence: evidenceSchema.parse({
          source: row.source,
          issuer: row.issuer,
          subject: row.subject,
          claims: JSON.parse(row.claims),
          verified_at: row.verified_at,
          key_id: row.key_id,
          result: row.result,
          reason: row.reason,
          payload_hash: row.payload_hash,
        }),
        decision_ref: row.decision_ref,
        agent_id: row.agent_id,
        agreement_id: row.agreement_id,
        action_id: row.action_id,
        kata_decision: row.kata_decision,
        audit_id: row.audit_id,
        created_at: row.created_at,
      }));
    });
  }

  async linkAudit(evidenceId: string, auditId: string): Promise<void> {
    await this.withClient((client) => client.query("UPDATE gab_external_evidence SET audit_id = $1 WHERE evidence_id = $2", [auditId, evidenceId]));
  }
}

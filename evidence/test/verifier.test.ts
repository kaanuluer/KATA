// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Synthetic keys only. Node crypto generates the key pairs. No vendor directory is contacted.

import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { exportJWK } from "jose";
import pg from "pg";
import { evidenceSchema } from "../src/schema.ts";
import { DirectoryRejected, assertPublicHttps } from "../src/ssrf.ts";
import { MemoryEvidenceStore, PostgresEvidenceStore, type EvidenceStore } from "../src/store.ts";
import { loadVectors, runVector } from "../src/vectors.ts";
import { evidenceVerifierEnabled, verifierFor } from "../src/verifier.ts";

const NOW = new Date("2026-11-13T12:00:00Z");
const DIRECTORY = "https://keys.example/jwks.json";
const PUBLIC = async () => ["8.8.8.8"];
const SQL = path.resolve("../service/kata_service/migrations/pending/021_external_evidence.sql");

class ScriptedFetch {
  calls = 0;
  urls: string[] = [];
  bodies: Uint8Array[];
  error: Error | null;
  constructor(bodies: Uint8Array[] = [], error: Error | null = null) {
    this.bodies = bodies;
    this.error = error;
  }
  async call(url: string): Promise<Uint8Array> {
    this.calls += 1;
    this.urls.push(url);
    if (this.error) throw this.error;
    const body = this.bodies.shift();
    if (!body) throw new Error("jwks fetch failed");
    return body;
  }
}

function b64url(data: Buffer): string {
  return data.toString("base64url");
}

function derToRaw(der: Buffer): Buffer {
  let offset = 2;
  if (der[0] !== 0x30) throw new Error("der");
  const readInt = () => {
    if (der[offset] !== 0x02) throw new Error("der int");
    const length = der[offset + 1];
    const bytes = der.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
    return bytes.length > 32 ? bytes.subarray(bytes.length - 32) : bytes;
  };
  const r = readInt();
  const s = readInt();
  const raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length);
  s.copy(raw, 64 - s.length);
  return raw;
}

async function jwkFor(publicKey: KeyObject, kid: string, alg: "EdDSA" | "ES256") {
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = "sig";
  return jwk;
}

function keyPair(alg: "EdDSA" | "ES256") {
  if (alg === "EdDSA") return generateKeyPairSync("ed25519");
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function compact(privateKey: KeyObject, payload: Record<string, unknown>, kid: string, alg: "EdDSA" | "ES256" | "HS256" | "none" = "EdDSA") {
  const header = b64url(Buffer.from(JSON.stringify({ alg, kid, typ: "JWT" })));
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const input = Buffer.from(`${header}.${body}`);
  if (alg === "none") return `${header}.${body}.`;
  if (alg === "HS256") {
    const mac = createHmac("sha256", Buffer.from("synthetic-hmac-key")).update(input).digest();
    return `${header}.${body}.${b64url(mac)}`;
  }
  const signature = alg === "EdDSA" ? sign(null, input, privateKey) : derToRaw(sign("sha256", input, privateKey));
  return `${header}.${body}.${b64url(signature)}`;
}

function payload(now: Date, extra: Record<string, unknown> = {}) {
  const shift = typeof extra.exp_shift === "number" ? extra.exp_shift : 600;
  const body: Record<string, unknown> = {
    exp: Math.floor(now.getTime() / 1000) + shift,
    iat: Math.floor(now.getTime() / 1000),
    iss: "https://issuer.example",
    jti: extra.jti ?? "jti-1",
    sub: "agent-synthetic",
  };
  for (const [key, value] of Object.entries(extra)) {
    if (key !== "exp_shift" && key !== "jti") body[key] = value;
  }
  if (typeof extra.jti === "string") body.jti = extra.jti;
  return body;
}

async function verifyToken(
  store: EvidenceStore,
  alg: "EdDSA" | "ES256",
  claims: Record<string, unknown>,
  options: { kid?: string; directory?: string; fetch?: ScriptedFetch; ttlSeconds?: number; maxEntries?: number; maxBytes?: number; resolve?: () => Promise<string[]> } = {},
) {
  const { publicKey, privateKey } = keyPair(alg);
  const kid = options.kid ?? "kid-1";
  const token = compact(privateKey, claims, kid, alg);
  const document = Buffer.from(JSON.stringify({ keys: [await jwkFor(publicKey, kid, alg)] }));
  const fetch = options.fetch ?? new ScriptedFetch([document]);
  const verifier = verifierFor("jwt", store, {
    fetch: (url) => fetch.call(url),
    resolve: options.resolve ?? PUBLIC,
    ttlSeconds: options.ttlSeconds,
    maxEntries: options.maxEntries,
    maxBytes: options.maxBytes,
  });
  const evidence = await verifier.verify({ token, directory: options.directory ?? DIRECTORY }, NOW);
  return { evidence, token, fetch, publicKey, privateKey };
}

async function stores(): Promise<Array<{ name: string; store: EvidenceStore }>> {
  const found: Array<{ name: string; store: EvidenceStore }> = [{ name: "memory", store: new MemoryEvidenceStore() }];
  const url = process.env.GAB_TEST_DATABASE_URL;
  if (!url) return found;
  const hostname = new URL(url).hostname;
  if (hostname !== "localhost" && hostname !== "127.0.0.1") throw new Error("GAB_TEST_DATABASE_URL must point at localhost");
  const schema = "evidence_node";
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await client.query(`CREATE SCHEMA ${schema}`);
  await client.query(`SET search_path TO ${schema}`);
  const sql = readFileSync(SQL, "utf8");
  for (const statement of sql.split(";").map((part) => part.trim()).filter(Boolean)) {
    await client.query(statement);
  }
  await client.end();
  found.push({ name: schema, store: new PostgresEvidenceStore(url, schema) });
  return found;
}

test("flag defaults off", () => {
  assert.equal(evidenceVerifierEnabled({}), false);
  assert.equal(evidenceVerifierEnabled({ GAB_EVIDENCE_VERIFIER: "0" }), false);
  assert.equal(evidenceVerifierEnabled({ GAB_EVIDENCE_VERIFIER: "1" }), true);
});

test("schema rejects a decision result", () => {
  assert.throws(() =>
    evidenceSchema.parse({
      source: "jwt",
      issuer: "https://issuer.example",
      subject: "agent-synthetic",
      claims: {},
      verified_at: "2026-11-13T12:00:00Z",
      key_id: "kid-1",
      result: "ALLOW",
      reason: "ok",
      payload_hash: "ab".repeat(32),
    }),
  );
});

test("synthetic vectors", async () => {
  const vectors = loadVectors(path.resolve("vectors/synthetic.json"));
  for (const vector of vectors) {
    const results = await runVector(vector, new MemoryEvidenceStore());
    for (const [key, value] of Object.entries(vector.expect)) {
      assert.equal(results.at(-1)?.[key as keyof (typeof results)[number]], value, vector.name);
    }
    if (vector.name === "synthetic-replay") {
      assert.equal(results[0].result, "valid");
      assert.equal(results[1].reason, "replay");
    }
  }
});

test("required jwt cases", async () => {
  for (const { name, store } of await stores()) {
    for (const alg of ["EdDSA", "ES256"] as const) {
      const kid = `kid-${alg}`;
      const directory = `https://${alg.toLowerCase()}.example/jwks.json`;
      const first = await verifyToken(store, alg, payload(NOW, { jti: `jti-${alg}-${name}` }), { kid, directory });
      assert.equal(first.evidence.result, "valid", name);
      assert.equal(first.evidence.reason, "ok");
      assert.equal(first.evidence.key_id, kid);
      assert.equal(first.evidence.payload_hash, createHash("sha256").update(Buffer.from(first.token.split(".")[1], "base64url")).digest("hex"));
      assert.equal(JSON.stringify(first.evidence).includes(first.token), false);
      assert.equal("kata_decision" in first.evidence, false);
      const cached = await verifierFor("jwt", store, { fetch: (url) => first.fetch.call(url), resolve: PUBLIC }).verify(
        { token: compact(first.privateKey, payload(NOW, { jti: `jti-${alg}-${name}-2` }), kid, alg), directory },
        NOW,
      );
      assert.equal(cached.result, "valid");
      assert.equal(first.fetch.calls, 1, `${alg} cache ${name}`);
    }

    const wrong = await verifyToken(store, "EdDSA", payload(NOW, { jti: `bad-${name}` }));
    const [head, body, signature] = wrong.token.split(".");
    const raw = Buffer.from(signature, "base64url");
    raw[raw.length - 1] ^= 0x01;
    const failed = await verifierFor("jwt", store, { fetch: (url) => wrong.fetch.call(url), resolve: PUBLIC }).verify(
      { token: `${head}.${body}.${b64url(raw)}`, directory: DIRECTORY },
      NOW,
    );
    assert.equal(failed.reason, "signature", name);

    const unknownFetch = new ScriptedFetch([Buffer.from(JSON.stringify({ keys: [await jwkFor(wrong.publicKey, "kid-other", "EdDSA")] }))]);
    const unknown = await verifierFor("jwt", store, { fetch: (url) => unknownFetch.call(url), resolve: PUBLIC }).verify(
      { token: compact(wrong.privateKey, payload(NOW, { jti: `unknown-${name}` }), "kid-1", "EdDSA"), directory: "https://unknown.example/jwks.json" },
      NOW,
    );
    assert.equal(unknown.reason, "unknown_kid");
    assert.equal(unknownFetch.calls, 1);

    const expiredFetch = new ScriptedFetch();
    const { privateKey } = keyPair("EdDSA");
    const expired = await verifierFor("jwt", store, { fetch: (url) => expiredFetch.call(url), resolve: PUBLIC }).verify(
      { token: compact(privateKey, payload(NOW, { jti: `expired-${name}`, exp_shift: -61 }), "kid-1", "EdDSA"), directory: DIRECTORY },
      NOW,
    );
    assert.equal(expired.reason, "expired");
    assert.equal(expiredFetch.calls, 0);

    const noneFetch = new ScriptedFetch();
    const noneHeader = b64url(Buffer.from(JSON.stringify({ alg: "none", kid: "kid-1", typ: "JWT" })));
    const noneBody = b64url(Buffer.from(JSON.stringify(payload(NOW, { jti: `none-${name}` }))));
    const none = await verifierFor("jwt", store, { fetch: (url) => noneFetch.call(url), resolve: PUBLIC }).verify(
      { token: `${noneHeader}.${noneBody}.`, directory: DIRECTORY },
      NOW,
    );
    assert.equal(none.reason, "alg_rejected");
    const mixedHeader = b64url(Buffer.from(JSON.stringify({ alg: "None", kid: "kid-1" })));
    const mixed = await verifierFor("jwt", store, { fetch: (url) => noneFetch.call(url), resolve: PUBLIC }).verify(
      { token: `${mixedHeader}.${noneBody}.x`, directory: DIRECTORY },
      NOW,
    );
    assert.equal(mixed.reason, "alg_rejected");
    const hs = await verifierFor("jwt", store, { fetch: (url) => noneFetch.call(url), resolve: PUBLIC }).verify(
      { token: compact(privateKey, payload(NOW, { jti: `hs-${name}` }), "kid-1", "HS256"), directory: DIRECTORY },
      NOW,
    );
    assert.equal(hs.reason, "alg_rejected");
    assert.equal(noneFetch.calls, 0);

    const ec = keyPair("ES256");
    const ed = keyPair("EdDSA");
    const mismatchFetch = new ScriptedFetch([Buffer.from(JSON.stringify({ keys: [await jwkFor(ed.publicKey, "kid-1", "EdDSA")] }))]);
    const mismatch = await verifierFor("jwt", store, { fetch: (url) => mismatchFetch.call(url), resolve: PUBLIC }).verify(
      { token: compact(ec.privateKey, payload(NOW, { jti: `mix-${name}` }), "kid-1", "ES256"), directory: `https://mix-${name}.example/jwks.json` },
      NOW,
    );
    assert.equal(mismatch.reason, "alg_mismatch");

    const replay = await verifyToken(store, "EdDSA", payload(NOW, { jti: `replay-${name}` }), { directory: `https://replay-${name}.example/jwks.json` });
    const again = await verifierFor("jwt", store, { fetch: (url) => replay.fetch.call(url), resolve: PUBLIC }).verify(
      { token: replay.token, directory: `https://replay-${name}.example/jwks.json` },
      NOW,
    );
    assert.equal(replay.evidence.result, "valid");
    assert.equal(again.reason, "replay");

    const within = await verifyToken(store, "EdDSA", payload(NOW, { jti: `skew-${name}`, exp_shift: -60 }), {
      directory: `https://skew-${name}.example/jwks.json`,
    });
    assert.equal(within.evidence.result, "valid", name);
    const outside = await verifierFor("jwt", store, { fetch: (url) => within.fetch.call(url), resolve: PUBLIC }).verify(
      { token: compact(within.privateKey, payload(NOW, { jti: `out-${name}`, exp_shift: -61 }), within.evidence.key_id, "EdDSA"), directory: `https://skew-${name}.example/jwks.json` },
      NOW,
    );
    assert.equal(outside.reason, "expired");

    const down = new ScriptedFetch([], new Error("directory unavailable"));
    const failedFetch = await verifyToken(store, "EdDSA", payload(NOW, { jti: `down-${name}` }), {
      fetch: down,
      directory: `https://down-${name}.example/jwks.json`,
    });
    assert.equal(failedFetch.evidence.result, "unverifiable");
    assert.equal(failedFetch.evidence.reason, "jwks_fetch_failed");

    const blocked = [
      "http://keys.example/jwks.json",
      "https://127.0.0.1/jwks.json",
      "https://10.1.2.3/jwks.json",
      "https://192.168.1.9/jwks.json",
      "https://172.16.0.4/jwks.json",
      "https://169.254.169.254/latest",
      "https://[::1]/jwks.json",
      "https://[fe80::1]/jwks.json",
      "https://localhost/jwks.json",
      "https://2130706433/jwks.json",
    ];
    const ssrfToken = compact(privateKey, payload(NOW, { jti: `ssrf-${name}` }), "kid-1", "EdDSA");
    for (const directory of blocked) {
      const fetch = new ScriptedFetch([Buffer.from("{}")]);
      const evidence = await verifierFor("jwt", store, { fetch: (url) => fetch.call(url), resolve: PUBLIC }).verify({ token: ssrfToken, directory }, NOW);
      assert.equal(evidence.reason, "directory_url_rejected", directory);
      assert.equal(fetch.calls, 0, directory);
    }
    const rebound = new ScriptedFetch([Buffer.from("{}")]);
    const reboundResult = await verifierFor("jwt", store, { fetch: (url) => rebound.call(url), resolve: async () => ["127.0.0.1"] }).verify(
      { token: ssrfToken, directory: "https://rebind.example/jwks.json" },
      NOW,
    );
    assert.equal(reboundResult.reason, "directory_url_rejected");
    assert.equal(rebound.calls, 0);
  }
});

test("generated ed25519 and es256 vectors run from a fixture file", async () => {
  const ed = keyPair("EdDSA");
  const ec = keyPair("ES256");
  const document = {
    version: 1,
    vectors: [
      {
        name: "generated-ed25519",
        source: "jwt",
        now: "2026-11-13T12:00:00Z",
        jwks: { keys: [await jwkFor(ed.publicKey, "kid-ed", "EdDSA")] },
        material: { directory: DIRECTORY, token: compact(ed.privateKey, payload(NOW, { jti: "vector-ed" }), "kid-ed", "EdDSA") },
        expect: { result: "valid", reason: "ok", key_id: "kid-ed" },
      },
      {
        name: "generated-es256",
        source: "jwt",
        now: "2026-11-13T12:00:00Z",
        jwks: { keys: [await jwkFor(ec.publicKey, "kid-ec", "ES256")] },
        material: { directory: DIRECTORY, token: compact(ec.privateKey, payload(NOW, { jti: "vector-ec" }), "kid-ec", "ES256") },
        expect: { result: "valid", reason: "ok", key_id: "kid-ec" },
      },
    ],
  };
  const directory = await mkdtemp(path.join(tmpdir(), "evidence-"));
  const file = path.join(directory, "generated.json");
  await writeFile(file, JSON.stringify(document));
  for (const vector of loadVectors(file)) {
    const fetch = new ScriptedFetch([Buffer.from(JSON.stringify(vector.jwks))]);
    const results = await runVector(vector, new MemoryEvidenceStore(), { fetch: (url) => fetch.call(url), resolve: PUBLIC });
    for (const [key, value] of Object.entries(vector.expect)) assert.equal(results.at(-1)?.[key as "result"], value);
  }
});

test("ssrf guard rejects a private literal before name resolution", async () => {
  await assert.rejects(() => assertPublicHttps("https://10.0.0.8/jwks.json", PUBLIC), DirectoryRejected);
  await assert.rejects(() => assertPublicHttps("http://8.8.8.8/jwks.json", PUBLIC), DirectoryRejected);
});

test("sensitive claim is not stored", async () => {
  const evidence = (await verifyToken(new MemoryEvidenceStore(), "EdDSA", payload(NOW, { jti: "secret", national_id: "123-45-6789" }))).evidence;
  assert.equal(evidence.reason, "sensitive_claim");
  assert.deepEqual(evidence.claims, {});
  assert.equal(JSON.stringify(evidence).includes("123-45-6789"), false);
});

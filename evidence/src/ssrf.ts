// Copyright 2026 Kaan Uluer
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// HTTPS directory URLs that resolve only to public addresses.

import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

const BLOCKED_NAMES = new Set(["localhost", "localhost.localdomain", "metadata.google.internal", "metadata.internal"]);

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("10.0.0.0", 8, "ipv4");
blocked.addSubnet("100.64.0.0", 10, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("172.16.0.0", 12, "ipv4");
blocked.addSubnet("192.0.0.0", 24, "ipv4");
blocked.addSubnet("192.0.2.0", 24, "ipv4");
blocked.addSubnet("192.168.0.0", 16, "ipv4");
blocked.addSubnet("198.18.0.0", 15, "ipv4");
blocked.addSubnet("198.51.100.0", 24, "ipv4");
blocked.addSubnet("203.0.113.0", 24, "ipv4");
blocked.addSubnet("224.0.0.0", 4, "ipv4");
blocked.addSubnet("::", 128, "ipv6");
blocked.addSubnet("::1", 128, "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");
blocked.addSubnet("ff00::", 8, "ipv6");

export class DirectoryRejected extends Error {
  constructor() {
    super("directory URL is not allowed");
  }
}

export class ResolveFailed extends Error {
  constructor() {
    super("directory name did not resolve");
  }
}

export type Resolve = (host: string) => Promise<string[]> | string[];

function addressBlocked(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return true;
  return blocked.check(address, family === 6 ? "ipv6" : "ipv4");
}

function ipv4Literal(host: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(host);
}

export async function assertPublicHttps(url: string, resolve: Resolve = defaultResolve): Promise<string> {
  if (!url || [...url].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)) {
    throw new DirectoryRejected();
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new DirectoryRejected();
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw new DirectoryRejected();
  }
  let host = parsed.hostname;
  if (!host) throw new DirectoryRejected();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.endsWith(".")) host = host.slice(0, -1);
  const lowered = host.toLowerCase();
  if (
    BLOCKED_NAMES.has(lowered) ||
    lowered.endsWith(".localhost") ||
    lowered.endsWith(".local") ||
    lowered.endsWith(".internal")
  ) {
    throw new DirectoryRejected();
  }
  if (/^\d+$/.test(lowered) || lowered.startsWith("0x")) throw new DirectoryRejected();
  if (ipv4Literal(lowered)) {
    const parts = lowered.split(".").map((part) => Number(part));
    if (parts.some((part, index) => part > 255 || (lowered.split(".")[index].length > 1 && lowered.split(".")[index].startsWith("0")))) {
      throw new DirectoryRejected();
    }
    if (addressBlocked(lowered)) throw new DirectoryRejected();
    return lowered;
  }
  if (isIP(lowered) !== 0) {
    if (addressBlocked(lowered)) throw new DirectoryRejected();
    return lowered;
  }
  let addresses: string[];
  try {
    addresses = await resolve(lowered);
  } catch {
    throw new ResolveFailed();
  }
  if (!addresses.length) throw new ResolveFailed();
  if (addresses.some((address) => addressBlocked(address))) throw new DirectoryRejected();
  return lowered;
}

export async function defaultResolve(host: string): Promise<string[]> {
  const records = await lookup(host, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

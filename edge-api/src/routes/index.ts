// Cloudflare Worker serving <10ms GET /v1/ip/:ip, GET /v1/asn/:asn,
// GET /v1/edl/:feed.txt, GET /v1/stix/bundle.json, GET /v1/misp/manifest.json.
// Backed by KV for sub-10ms reads with D1 fallback.

export interface Env {
  KV: KVNamespace;
  D1: D1Database;
}

// Reputation record stored in KV.
interface IPReputation {
  ip: string;
  score: number;
  ttl: string;
  asn: string;
  geo: string;
  updated_at: string;
}

interface ASNReputation {
  asn: string;
  score: number;
  org: string;
  country: string;
  updated_at: string;
}

// KV key prefixes
const IP_PREFIX = "ip:";
const ASN_PREFIX = "asn:";
const STIX_BUNDLE_KEY = "stix:bundle";
const MISP_MANIFEST_KEY = "misp:manifest";

// Valid EDL feed names (whitelist to prevent enumeration)
const VALID_FEEDS = new Set(["blocklist", "malware", "scanner", "c2"]);

function isValidIP(ip: string): boolean {
  // IPv4 validation
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const m = ip.match(ipv4Regex);
  if (m) {
    for (let i = 1; i <= 4; i++) {
      const octet = parseInt(m[i], 10);
      if (octet < 0 || octet > 255) return false;
    }
    return true;
  }
  // IPv6 validation (simplified: hex digits and colons)
  if (ip.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.split(":").length >= 2;
  }
  return false;
}

function normalizeIP(ip: string): string {
  // Lowercase hex digits for consistent cache keys (IPv4 unaffected)
  return ip.toLowerCase();
}

function isValidASN(asn: string): boolean {
  return /^(AS)?\d{1,10}$/.test(asn);
}

function normalizeASN(asn: string): string {
  const upper = asn.toUpperCase();
  return upper.startsWith("AS") ? upper : "AS" + upper;
}

function parseTTLSeconds(ttl: string): number {
  const match = ttl.match(/^(\d+)([smhd]?)$/);
  if (!match) return 86400;
  const value = parseInt(match[1], 10);
  const unit = match[2] || "h";
  switch (unit) {
    case "s": return value;
    case "m": return value * 60;
    case "h": return value * 3600;
    case "d": return value * 86400;
    default: return value * 3600;
  }
}

function jsonResponse(data: unknown, status: number = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Health check - GET only
    if (path === "/healthz") {
      if (method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return new Response("ok", { status: 200 });
    }

    // Only GET is supported for all API routes
    if (method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // GET /v1/ip/:ip
    const ipMatch = path.match(/^\/v1\/ip\/([^/]+)$/);
    if (ipMatch) {
      const ip = normalizeIP(ipMatch[1]);
      if (!isValidIP(ip)) {
        return jsonResponse({ error: "invalid ip" }, 400);
      }
      return handleIPLookup(env, ip, ctx);
    }

    // GET /v1/asn/:asn
    const asnMatch = path.match(/^\/v1\/asn\/([^/]+)$/);
    if (asnMatch) {
      const asn = normalizeASN(asnMatch[1]);
      if (!isValidASN(asn)) {
        return jsonResponse({ error: "invalid asn" }, 400);
      }
      return handleASNLookup(env, asn, ctx);
    }

    // GET /v1/edl/:feed.txt
    const edlMatch = path.match(/^\/v1\/edl\/([^/]+)\.txt$/);
    if (edlMatch) {
      const feed = edlMatch[1];
      if (!VALID_FEEDS.has(feed)) {
        return jsonResponse({ error: "invalid feed" }, 400);
      }
      return handleEDL(env, feed);
    }

    // GET /v1/stix/bundle.json
    if (path === "/v1/stix/bundle.json") {
      return handleSTIXBundle(env);
    }

    // GET /v1/misp/manifest.json
    if (path === "/v1/misp/manifest.json") {
      return handleMISPManifest(env);
    }

    return new Response("not found", { status: 404 });
  },
};

async function handleIPLookup(env: Env, ip: string, ctx: ExecutionContext): Promise<Response> {
  const key = IP_PREFIX + ip;
  const cached = await env.KV.get(key, "json");

  if (cached !== null) {
    const rep = cached as IPReputation;
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  // KV miss — fall back to D1
  let rep: IPReputation | null = null;
  try {
    const result = await env.D1.prepare(
      "SELECT score, ttl, asn, geo, updated_at FROM ip_reputation WHERE ip = ?"
    ).bind(ip).first();

    if (result) {
      rep = {
        ip,
        score: Number(result.score),
        ttl: String(result.ttl),
        asn: String(result.asn ?? ""),
        geo: String(result.geo ?? ""),
        updated_at: String(result.updated_at),
      };
    }
  } catch (e) {
    console.error("D1 lookup failed for IP:", ip, e);
  }

  if (rep) {
    // Backfill KV in background (don't block response)
    ctx.waitUntil(
      env.KV.put(key, JSON.stringify(rep), { expirationTtl: parseTTLSeconds(rep.ttl) }).catch(() => {})
    );
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  return new Response(JSON.stringify({ ip, error: "not found" }), {
    status: 404,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleASNLookup(env: Env, asn: string, ctx: ExecutionContext): Promise<Response> {
  const key = ASN_PREFIX + asn;
  const cached = await env.KV.get(key, "json");

  if (cached !== null) {
    const rep = cached as ASNReputation;
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  // KV miss — fall back to D1
  let rep: ASNReputation | null = null;
  try {
    const result = await env.D1.prepare(
      "SELECT score, org, country, updated_at FROM asn_reputation WHERE asn = ?"
    ).bind(asn).first();

    if (result) {
      rep = {
        asn,
        score: Number(result.score),
        org: String(result.org),
        country: String(result.country),
        updated_at: String(result.updated_at),
      };
    }
  } catch (e) {
    console.error("D1 lookup failed for ASN:", asn, e);
  }

  if (rep) {
    // Backfill KV in background
    ctx.waitUntil(
      env.KV.put(key, JSON.stringify(rep), { expirationTtl: parseTTLSeconds(rep.ttl) }).catch(() => {})
    );
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  return new Response(JSON.stringify({ asn, error: "not found" }), {
    status: 404,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleEDL(env: Env, feed: string): Promise<Response> {
  // Firewall-ready plain-text blocklist: one IP per line
  const key = "edl:" + feed;
  const cached = await env.KV.get(key, "text");

  if (cached !== null) {
    return new Response(cached, {
      status: 200,
      headers: {
        "Content-Type": "text/plain",
        "Cache-Control": "public, max-age=60",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  return new Response("# empty\n", {
    status: 200,
    headers: {
      "Content-Type": "text/plain",
      "Cache-Control": "public, max-age=60",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function handleSTIXBundle(env: Env): Promise<Response> {
  const cached = await env.KV.get(STIX_BUNDLE_KEY, "json");

  if (cached !== null) {
    return new Response(JSON.stringify(cached), {
      status: 200,
      headers: {
        "Content-Type": "application/stix+json;version=2.1",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  return new Response(
    JSON.stringify({ type: "bundle", spec_version: "2.1", objects: [] }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/stix+json;version=2.1",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
}

async function handleMISPManifest(env: Env): Promise<Response> {
  const cached = await env.KV.get(MISP_MANIFEST_KEY, "json");

  if (cached !== null) {
    return new Response(JSON.stringify(cached), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  return new Response(JSON.stringify({ events: [] }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

// Cloudflare Worker serving <10ms GET /v1/ip/:ip, GET /v1/asn/:asn,
// GET /v1/edl/:feed.txt, GET /v1/stix/bundle.json, GET /v1/misp/manifest.json.
// Backed by KV for sub-10ms reads.

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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check
    if (path === "/healthz") {
      return new Response("ok", { status: 200 });
    }

    // GET /v1/ip/:ip
    const ipMatch = path.match(/^\/v1\/ip\/([^/]+)$/);
    if (ipMatch && request.method === "GET") {
      return handleIPLookup(env, ipMatch[1]);
    }

    // GET /v1/asn/:asn
    const asnMatch = path.match(/^\/v1\/asn\/([^/]+)$/);
    if (asnMatch && request.method === "GET") {
      return handleASNLookup(env, asnMatch[1]);
    }

    // GET /v1/edl/:feed.txt
    const edlMatch = path.match(/^\/v1\/edl\/([^/]+)\.txt$/);
    if (edlMatch && request.method === "GET") {
      return handleEDL(env, edlMatch[1]);
    }

    // GET /v1/stix/bundle.json
    if (path === "/v1/stix/bundle.json" && request.method === "GET") {
      return handleSTIXBundle(env);
    }

    // GET /v1/misp/manifest.json
    if (path === "/v1/misp/manifest.json" && request.method === "GET") {
      return handleMISPManifest(env);
    }

    return new Response("not found", { status: 404 });
  },
};

async function handleIPLookup(env: Env, ip: string): Promise<Response> {
  const key = IP_PREFIX + ip;
  const cached = await env.KV.get(key, "json");

  if (cached) {
    const rep = cached as IPReputation;
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
    });
  }

  // Cache miss — return not found (aggregator populates KV asynchronously)
  return new Response(JSON.stringify({ ip, score: 0, error: "not found" }), {
    status: 404,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleASNLookup(env: Env, asn: string): Promise<Response> {
  const key = ASN_PREFIX + asn;
  const cached = await env.KV.get(key, "json");

  if (cached) {
    const rep = cached as ASNReputation;
    return new Response(JSON.stringify(rep), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
    });
  }

  return new Response(JSON.stringify({ asn, score: 0, error: "not found" }), {
    status: 404,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleEDL(env: Env, feed: string): Promise<Response> {
  // Firewall-ready plain-text blocklist: one IP per line
  const key = "edl:" + feed;
  const cached = await env.KV.get(key, "text");

  if (cached) {
    return new Response(cached as string, {
      status: 200,
      headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=60" },
    });
  }

  return new Response("# empty\n", {
    status: 200,
    headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=60" },
  });
}

async function handleSTIXBundle(env: Env): Promise<Response> {
  const cached = await env.KV.get(STIX_BUNDLE_KEY, "json");

  if (cached) {
    return new Response(cached as string, {
      status: 200,
      headers: {
        "Content-Type": "application/stix+json;version=2.1",
        "Cache-Control": "public, max-age=300",
      },
    });
  }

  return new Response(
    JSON.stringify({ type: "bundle", spec_version: "2.1", objects: [] }),
    {
      status: 200,
      headers: { "Content-Type": "application/stix+json;version=2.1" },
    },
  );
}

async function handleMISPManifest(env: Env): Promise<Response> {
  const cached = await env.KV.get(MISP_MANIFEST_KEY, "json");

  if (cached) {
    return new Response(cached as string, {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
    });
  }

  return new Response(JSON.stringify({ events: [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

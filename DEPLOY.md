# nullpot Deployment Guide

nullpot has four independently deployable components:

1. **Static decoy site** (`decoys/ai-compute/`) — GitHub Pages, Netlify, Vercel, Cloudflare Pages
2. **Go sensor** (`sensors/cmd/sensor/`) — VPS/VM (requires arbitrary port binding)
3. **Go aggregator** (`aggregator/cmd/aggregator/`) — Render, Fly, EC2, etc.
4. **Cloudflare Worker** (`edge-api/`) — Cloudflare Workers + KV + D1 + Workers AI

---

## 1. Static Decoy Site

### GitHub Pages
```bash
# In GitHub repo Settings > Pages:
# Source: Deploy from a branch
# Branch: main, folder: /decoys/ai-compute
```

### Netlify
```bash
# Connect repo, set build command: echo 'static site'
# Publish directory: decoys/ai-compute
# Or use netlify.toml (already included)
netlify deploy --dir=decoys/ai-compute --prod
```

### Vercel
```bash
# Connect repo, Vercel auto-detects vercel.json
# Or use CLI:
vercel --prod decoys/ai-compute
```

### Cloudflare Pages
```bash
# Connect GitHub repo, set:
#   Production branch: main
#   Build command: (none)
#   Build output directory: decoys/ai-compute
# Or use Wrangler:
wrangler pages deploy decoys/ai-compute --project-name=nullpot-decoy
```

### Other static hosts
- **Firebase Hosting**: `firebase deploy --only hosting`
- **Surge.sh**: `surge decoys/ai-compute nullpot-decoy.surge.sh`
- **GitLab Pages**: `.gitlab-ci.yml` with `pages` job
- **Azure Static Web Apps**: Connect repo, set `app_location: decoys/ai-compute`

---

## 2. Go Sensor (requires VPS/VM)

The sensor binds arbitrary TCP ports (SSH :2222, raw TCP :6379, HTTP :8080). Render and similar HTTP-only platforms **will not work** for full trap coverage.

```bash
# Build
go build -o sensor ./sensors/cmd/sensor

# Run
PORT=8080 AGGREGATOR_URL=https://aggregator.example.com/v1/ingest ./sensor

# With systemd, see sensors/cmd/sensor/ for flags
```

**Recommended VPS providers:** Hetzner, DigitalOcean, Linode, EC2, Lightsail (any with full port control)

---

## 3. Go Aggregator

Can deploy on any HTTP-capable platform:

```bash
# Build
go build -o aggregator ./aggregator/cmd/aggregator

# Run (Render, Fly, EC2, etc.)
PORT=8081 CF_ACCOUNT_ID=... CF_API_TOKEN=... ./aggregator
```

**Render:** Create Web Service, connect repo, build command: `go build -o aggregator ./aggregator/cmd/aggregator`, start command: `./aggregator`

---

## 4. Cloudflare Edge API (Worker + KV + D1 + AI)

### Prerequisites
- Cloudflare account with Workers, KV, D1, Workers AI enabled
- `wrangler` CLI installed: `npm install -g wrangler`

### Step 1: Create KV namespace
```bash
wrangler kv:namespace create "KV"
# Note the namespace ID, update wrangler.toml
```

### Step 2: Create D1 database
```bash
wrangler d1 create nullpot-edge-db
# Note the database ID, update wrangler.toml
```

### Step 3: Apply D1 schema
```bash
wrangler d1 execute nullpot-edge-db --file=./edge-api/migrations/schema.sql
```

### Step 4: Deploy Worker
```bash
cd edge-api
wrangler deploy
```

### Required secrets
```bash
wrangler secret put CF_ACCOUNT_ID
wrangler secret put CF_API_TOKEN
wrangler secret put CF_KV_NAMESPACE
wrangler secret put CF_D1_DATABASE
```

### GitHub Actions deployment (auto)
The `.github/workflows/ci.yml` deploys both the static site and Worker on push to `main`. Set these repo secrets:
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

---

## Architecture Overview

```
Attacker Internet
     |
     v
+------------+      HTTP traps     +------------------+
| Decoy Site |-------------------->|  Go Sensor       |
| (static)   |  /contact, /login   |  :8080 HTTP      |
+------------+  /signup, OAuth     |  :2222 SSH       |
     |                            |  :6379 Raw TCP   |
     | telemetry beacons          +--------+-----------+
     |                                         |
     v                                         v
+------------------+                   +------------------+
|  Go Aggregator   |<------------------|  Go Sensor       |
|  /v1/ingest      |  gzip JSON POST |  (shipper)       |
+------------------+                   +------------------+
     |
     | batched KV/D1 writes (free-tier capped)
     v
+------------------+
| Cloudflare Edge  |
| Worker + KV + D1 |
| /v1/ip/:ip       |
| /v1/asn/:asn     |
| /v1/edl/:feed.txt|
+------------------+
```

---

## Environment Variables Summary

| Component | Variable | Required | Default |
|-----------|----------|----------|---------|
| Sensor | `AGGREGATOR_URL` | Yes | `http://localhost:8081/v1/ingest` |
| Sensor | `PORT` | No | `:8080` |
| Sensor | `SSH_LISTEN` | No | `:2222` |
| Sensor | `RAW_TCP_LISTEN` | No | `:6379` |
| Sensor | `PERSONAS_DIR` | No | `sensors/personas` |
| Aggregator | `PORT` | No | `:8081` |
| Aggregator | `CF_ACCOUNT_ID` | No | (disables CF sync) |
| Aggregator | `CF_API_TOKEN` | No | |
| Aggregator | `CF_KV_NAMESPACE` | No | |
| Aggregator | `CF_D1_DATABASE` | No | |
| Decoy site | `CF_WEB_ANALYTICS_TOKEN` | No | (injected via CI/CD) |
| Edge Worker | `KV` binding | Yes | via wrangler.toml |
| Edge Worker | `D1` binding | Yes | via wrangler.toml |
| Edge Worker | `AI` binding | Yes | via wrangler.toml |
| CI/CD | `CLOUDFLARE_API_TOKEN` | Yes | for Pages + wrangler deploy |
| CI/CD | `CLOUDFLARE_ACCOUNT_ID` | Yes | for Pages + wrangler deploy |
| CI/CD | `CF_WEB_ANALYTICS_TOKEN` | Yes | injected into decoy site HTML |

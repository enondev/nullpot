# Nexus Compute Decoy Site
#
# Purpose: Static-site telemetry token carrier for the nullpot Threat & Abuse
# Intelligence Platform. Hosted on GitHub Pages / Netlify / any free static
# host to expand the reconnaissance surface without exposing the Go sensor.
#
# Architecture:
#   - Each page embeds telemetry token IDs (base64/hex-prefixed) in visible
#     text, hidden inputs, data attributes, hrefs, and HTML comments.
#   - telemetry.js obfuscates the aggregator callback URL (base64 split across
#     concatenation) and prefixes token IDs at runtime, so naive scanners
#     cannot grep for a static endpoint or token pattern.
#   - telemetry.js captures every user interaction as telemetry events:
#       * Page loads (pageview) with full browser fingerprint
#         (screen, timezone, language, platform, hardware concurrency, UA,
#         canvas rendering, WebGL renderer/vendor)
#       * All clicks (tag, href, text) - no element is missed
#       * Mouse movement (sampled 1 in 5 events, x/y coordinates)
#       * Scroll depth percentage (only on new max depth)
#       * Keyboard activity (key count, sampled 1 in 5)
#       * Page visibility changes (tab switch / hide - strong bot signal)
#     All events are batched (10 events or 3s flush) and sent via
#     navigator.sendBeacon to POST /v1/telemetry/callback.
#   - Chaotic jitter (random micro-movements) and randomly-disabled buttons
#     disrupt automated clicking and slow down scrapers.
#   - Recursive topology pages (topology.html) and iframe recursion trap
#     automated crawlers in infinite link graphs.
#   - Fake OAuth buttons (Google, GitHub, Microsoft, Okta) - some redirect to
#     the topology trap (infinite recursion), others silently POST then show
#     a fake "temporarily unavailable" error.
#   - Fake login/signup forms capture credentials and POST them to the
#     aggregator before simulating an error/success to keep the attacker
#     engaged.
#   - D1-backed contact form submits to an external Workers endpoint.
#   - Honeypot links (/admin, /.env, /phpmyadmin, etc.) are disallowed in
#     robots.txt but present in page source to lure automated path scanners.
#
# Pages:
#   index.html        - Landing page with fake CLI config, support email,
#                       Slack invite, hidden AWS/Stripe/SSH keys
#   login.html        - Fake login capturing credentials (simulated error)
#   signup.html       - Fake signup capturing profile + GPU spend estimates
#   dashboard.html    - Fake dashboard with API keys, billing DB creds, IAM
#   api.html          - Fake API docs with bearer tokens, webhook URLs
#   pricing.html      - Fake pricing with discount codes, billing DB string
#   products.html     - GPU product pages with internal partner portal links
#   topology.html     - Recursive infrastructure dependency graph (tarpit)
#   console.html      - Fake ops console with jitter + disabled buttons
#   contact.html      - D1-backed contact form (newsletter signup)
#   404.html          - Custom 404 with hidden internal monitoring endpoints
#
# Deployment:
#   1. The aggregator callback URL is base64-obfuscated in telemetry.js. Decode
#      and replace the atob input with your aggregator's public
#      /v1/telemetry/callback endpoint.
#   2. Rotate all token IDs per deployment so token reuse can be attributed
#      to a specific infrastructure instance.
#   3. Point your domain's A/AAAA or CNAME at the static host.
#   4. Inject CF_WEB_ANALYTICS_TOKEN at CI/CD for Cloudflare Web Analytics.
#
# Related AGENTS.md rules:
#   - Canary Token Injection & Callback Attribution (rule 3)
#   - Safe Payload Handling & Legal Guardrails (rule 6): never execute
#     captured content; this site only records form submissions and beacons.

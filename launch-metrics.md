# StockyShift Launch Metrics

Published: 2026-08-11 — https://apps.shopify.com/stockyshift
Reference: 127809

| Date | Installs | Active installs | In trial | Subscribed | Uninstalls |
|------|----------|-----------------|----------|------------|------------|
| 2026-08-11 | 0 | 0 | 0 | 0 | 0 | (published today — baseline) |

## How to snapshot

1. Set the `METRICS_TOKEN` env var on Render (any random string you choose)
2. Deploy the latest server.js (git push to Render)
3. From the repo:

```bash
export METRICS_TOKEN="<your token>"
./scripts/metrics.sh
```

Or fetch manually:

```bash
curl -H "x-metrics-token: <your token>" https://stockyshift.onrender.com/admin/metrics
```

## What the endpoint returns (aggregate only — no shop names, no PII)

- total_installs / active_installs / uninstalls / installs_today
- status breakdown: pending, trial, active, cancelled, declined, expired, frozen

## Watchpoints for the first weeks

- **Installs ≈ 0 after 1 week** → the store listing isn't converting. Revisit
  listing copy/screenshots, check search placement ("inventory", "reorder",
  "purchase order").
- **Trial starts but 0 conversions** → onboarding or value-not-landing problem.
- **Installs -> uninstalls within 48h** → OAuth/install friction or expectation mismatch.
- **Conversion rate**: active ÷ (installs - uninstalls). 2-5% is a healthy start.
- Reviews matter most at the start — 5+ reviews with 4.5★ average unlocks
  category visibility.
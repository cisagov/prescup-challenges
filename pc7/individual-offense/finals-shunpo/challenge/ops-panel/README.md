# Ops Panel Service

Restricted operations panel used for the offensive close-out of SHUNPO.

## Purpose

Recovered earlier-stage material feeds directly into this service:

- `OPS_ADMIN_PASS` ← token 1
- `ROUTE_KEY` ← token 2
- `INTERNAL_SIGNING_KEY` ← token 3
- `BRIDGE_TICKET` ← token 4
- `FINAL_TOKEN` ← token 5 (consumed by the constrained bridge workflow)

## Exposed Routes

- `/login` — operator authentication
- `/dashboard` — overview and response-detail control
- `/diagnostics/relay` — HTTP maintenance relay
- `/diagnostics/coap` — constrained CoAP bridge relay
- `/internal/brief` — loopback-only internal brief endpoint
- `/health` — health endpoint

## Intentional Weaknesses

- The HTTP relay validates the trusted first hop, then follows redirects to the terminal destination.
- The dashboard exposes an open maintenance redirect.
- The constrained bridge validates the raw telemetry namespace and blocks dot-segments only after the first decode pass, allowing a double-decoding mismatch when the upstream normalizes the path.

# Constrained CoAP Bridge Service

Internal maintenance plane for SHUNPO.

The service accepts bridge-authenticated UDP messages from the operations panel, normalizes the target path after double decoding, and exposes:

- `/telemetry/pulse`
- `/telemetry/catalog`
- hidden admin workflow:
  - `/admin/bootstrap`
  - `/admin/material`
  - `/admin/finalize`

The hidden admin workflow requires:

- token 4 as the bridge ticket,
- token 2 as the route key,
- token 3 for proof generation,
- and token 5 is returned on successful finalize.

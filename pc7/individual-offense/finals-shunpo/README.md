# SHUNPO

⚡ Flash Step. One spy. Five operational recoveries. Reconstruct the tradecraft, breach the trust boundary, and force the final relay.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

For more information on these roles, please visit: https://niccs.cisa.gov/tools/nice-framework.

## Background

Kitsune (former field agent and USAF S.E.R.E Trainer) disappeared during a covert support mission that chained together three categories of tradecraft: 

1. forensic fragments hidden in traffic,
2. trusted relay abuse through an operations workflow,
3. constrained bridge translation into an internal maintenance plane.

The first three recoveries are deterministic and can be solved from the evidence package plus the replay export produced by the dashboard. The fourth and fifth recoveries require live exploitation against the deployed services.

## Token Notes

- Token 1 recovers the reused operations panel password.
- Token 2 recovers the route key used by both relays.
- Token 3 recovers the internal signing key.
- Token 4 is the bridge ticket recovered by exploiting the HTTP maintenance relay.
- Token 5 is the final relay token recovered by abusing the constrained CoAP bridge.

### Formatting

All tokens take the following format:

`PCCC{SHN-A#-xxxxxxxx}`

### Token 4

The initial `nonce` value does not need to be guessed. Any sufficiently long value is acceptable, provided the same value is used in both the URL and the signature input.

### Token 5

Some bridge-mediated admin sequences are `stateful`. Preserve values returned by earlier steps and use fresh timestamps when constructing follow-on requests.

## System and Tool Credentials

| service | location |
|---|---|
| Evidence Dashboard | `http://sp-dashboard.ninja:3000` |
| Replay Controller | `http://sp-replay.ninja:7000` |
| Operations Panel | `http://sp-ops.ninja:8080` |
| Constrained CoAP Service | `sp-coap.ninja udp/5683` |

## Notes

Attacking or unauthorized access to the Challenge Platform itself is forbidden.
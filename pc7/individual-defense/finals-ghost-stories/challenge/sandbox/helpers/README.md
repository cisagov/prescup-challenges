# Sandbox helpers

Pre-installed analysis tools (use directly from any Jupyter cell or terminal):

| Tool | Purpose |
|---|---|
| `volatility3` (Python module + `vol` CLI) | Memory/registry analysis |
| `regipy` | Windows registry hive parser |
| `python-evtx` | Read .evtx files programmatically |
| `python-registry` | Older registry parser (alternative to regipy) |
| `pefile` | PE binary inspection |
| `capstone` | Disassembler |
| `oletools` | Office document inspection |

## Helper scripts in this directory

- **`parse_reg.py`** — quickstart for parsing Windows `.reg` exports.
  Demonstrates value enumeration under arbitrary keys.

## Common entry points

Fetch artifacts from the artifact server:

```python
import urllib.request
with urllib.request.urlopen("http://artifacts.pccc/install_obf.bat") as r:
    data = r.read()
```

Query the live Kibana directly from Python (when the UI is awkward):

```python
import requests
r = requests.get("http://kibana:5601/api/console/proxy?path=/sysmon-*/_search&method=GET",
                 headers={"kbn-xsrf": "true"})
```

(Kibana isn't actually reachable as `kibana` from the sandbox — use the
UI at `http://kibana.pccc:5601`. The browser is the right tool.)

# Operation Ghost Stories

A long-running asset went quiet. The evidence didn't.

**NICE Work Roles:**
- [Incident Response](https://niccs.cisa.gov/tools/nice-framework)
- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)
- [Threat Analysis](https://niccs.cisa.gov/tools/nice-framework)

## Background

Skyloom Aerospace runs classified airframe research for the US Navy out
of a Bellevue, WA campus. At 02:17 local, the overnight SOC analyst on
console caught a chain of suspicious child processes spawning off
`cmd.exe` on an engineering workstation — `eng-bell-04` — followed by a
sustained outbound TCP connection to a public tunneling service. By the
time the on-call lead pulled the cable at 02:34, the implant had been
on the box for an unknown amount of time and had executed at least
seventeen distinct PowerShell child commands.

The host was imaged before reboot. The artifact set on `artifacts.pccc`
contains:

- Sysmon and PowerShell EVTX logs (already shipped to Elasticsearch)
- Registry hive exports (`SOFTWARE`, `NTUSER.DAT`)
- A WMI repository snapshot and scheduled-task XML exports
- Two recovered files: an obfuscated batch script and a Python implant
- A PCAP of the outbound C2 traffic

The implant's behavior reads like classic tradecraft — multiple
redundant footholds in case any single one is burned, anti-surveillance
checks before talking to its handler, and a challenge-response
"activation phrase" before the courier channel will accept commands.
The Bureau code-named its 2010 investigation of a similar deep-cover
network *Operation Ghost Stories*. Your job is the same one
Counterintelligence (CI) had then: identify the asset, walk every dead
drop they left behind,
recover their handler's instructions, and determine what was passed
before the line went dead.

## Getting Started

Use the provided Kali host to investigate. All systems and access
details are listed in the **Systems and Tools** table below.

The artifact server is read-only. The sandbox is the only place you
should execute recovered code; do not run `install_obf.bat` or `svc.py`
outside it.

> **Note:** Kibana and its backing log store may take up to 5 minutes
> to become available after the challenge starts. The artifact server,
> sandbox, and handler are available immediately — begin your
> investigation there while the logs finish loading.

## Tokens

Tokens are formatted as `PCCC{GS-T?-????????}`.

1. **Asset identification.** Recover the SHA256 of the dropper that
   initiated the compromise. Submit the resulting token.
2. **Defensive evasion.** The asset disabled monitoring before deploying
   the implant. Identify the full PowerShell command used to disable
   monitoring and submit it to `challenge.pccc`.
3. **Dead-drop enumeration.** The asset established multiple
   independent footholds on the host. Enumerate every one and submit
   structured evidence (mechanism type + identifier) to
   `challenge.pccc`. The token is awarded once the full set is verified.
4. **Handler's instructions.** The dropper carries an embedded payload
   that is extracted at runtime via a self-referential routine.
   Reproduce the extraction in the sandbox and submit the SHA256 of the
   decoded Python implant.
5. **Courier intercept.** The implant authenticates to its handler with
   a challenge-response. Replicate the activation phrase against
   `handler.pccc:41243` and recover the token returned by the listener.

## Rules

- All execution of recovered samples must happen inside the sandbox
  container. The recovered batch script has been declawed (destructive
  commands replaced with marker strings), but treat it as live malware.
- The artifact server is read-only — do not attempt to modify hosted
  files.
- Token 3's grading endpoint rate-limits submissions; structured
  evidence is required.

## Systems and Tools

| System | URL / Access | Username | Password | Purpose |
|---|---|---|---|---|
| Kali workstation | Desktop (VNC) | user | password | Primary investigation host |
| Challenge progress | `http://challenge.pccc/` | — | — | Token submission, evidence downloads |
| Kibana | `http://kibana.pccc:5601` | — | — | Sysmon / PowerShell log search |
| Artifact server | `http://artifacts.pccc/` | — | — | Registry hives, WMI snapshot, scheduled-task XML, recovered files, PCAP |
| Analysis sandbox | `http://sandbox.pccc:8888` | — | — | Jupyter with Volatility 3, regipy, python-evtx |
| Handler channel replay | `tcp://handler.pccc:41243` | — | — | Captured replay of the C2 listener; use for Token 5 |

## Note

Attacking or unauthorized access to `challenge.pccc` is forbidden. You
may only use the provided web page to view challenge progress and
download any challenge artifacts that are provided.

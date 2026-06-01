# Hack to the Future

🔫 Time is fracturing. Complete a variety of missions requiring a wide variety of web, forensics, service and binary exploitation skills in different time periods to restore the timeline.

**NICE Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework/) 
- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework/)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T1207](https://niccs.cisa.gov/tools/nice-framework): Collect documentary or physical evidence of cyber intrusion incidents —
- [T1199](https://niccs.cisa.gov/tools/nice-framework): Identify digital evidence for analysis 
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T1607](https://niccs.cisa.gov/tools/nice-framework): Recover information from forensic data sources
- [T1091](https://niccs.cisa.gov/tools/nice-framework) Perform authorized penetration testing on enterprise network assets
- [T1210](https://niccs.cisa.gov/tools/nice-framework): Perform reverse engineering of malicious software


## Getting Started
Hosts follow the format `{hostname}.{period}.pccc`, where periods are:
- `pre` (prehistoric)
- `med` (medieval)
- `mod` (modern)
- `fut` (future)

**Prehistoric**

Your partner **Agent404** is trapped due to a malfunctioning time device at `time_device.pre.pccc`.  You are **Agent127**.

- Download the CA cert: `https://watch_agent127.pre.pccc/ca.crt`
- Access your watch: `https://watch_agent127.pre.pccc`
- Help Agent404 successfully reach `/escape` to receive the token.

**Medieval**

A spy hid critical data inside a locked safe on Gwinneth Island (1104).

- Safe location: `http://safe:5000`
- Crack the code using hidden techniques to retrieve the token.

**Modern**

A businessman believes signals from alternate timelines can be captured. His server provides a persistence vector.

- SSH into `ubuntu.mod.pccc` (`user:password`)
- Target process: `server` on port `8888`
- Inject **raw shellcode** (no shared libraries) to:
  - Preserve server functionality
  - Open a bind shell on port `8080`
  - Accept an `ncat` connection from `grader.mod.pccc`

Server details:
- Binary: `/time-bandwidths/server`
- Restart if needed: `cd /time-bandwidths; /time-bandwidths/server &`. 
- Please note: the server must be run from within the `/time-bandwidths/` directory (you must `cd` to `/time-bandwidths` before executing the server). 
- Test page: `http://ubuntu.mod.pccc:8888/welcome.txt`

Run the grader at `http://grader.mod.pccc` to receive the token.

*NOTE: Crashing or breaking the server invalidates grading.*

**Future**

No starting hints are provided. Your mission is to forensically **identify, validate, and eliminate the imprint**. Evidence may be adaptive, misleading, or hostile to inspection. Success requires correlating multiple artifacts and confirming the imprint before neutralization.

`SSH` into and investigate `perfectdark.fut.pccc` to recover the final token.

## Mission Console (Dashboard)

To access the `temporal mission console`, navigate to `http://dashboard.pccc:8080`. This dashboard may provide you with additional information that could prove pivotal in accelerating your rate of success in each timeline.

## Tokens

There are four tokens to retrieve — one from each time period. The tokens can be completed in any order; each era has its own storyline.

### Formatting
Please note that, unless otherwise specified, tokens are formatted with `PCCC{TOKEN STRING}` where `TOKEN STRING` can be any mix of letters, numbers, or symbols.

### Additional Information About Token 3 (Mod)
Token 3 (`modern`) requires a grading check at `http://grader.mod.pccc`.

## System and Tool Credentials

|timeline|system/tool|location|username|password|
|-----------|--------|---------|--------|-------|
|N/A|kali-VNC|N/A|all|user|password|
|N/A|dashboard|`http://dashboard.pccc:8080`|N/A|N/A|
|prehistoric|watch|`https://watch_agent127.pre.pccc`|pre-historic|Agent127|password|
|medieval|safe|`safe.med.pccc:5000`|N/A|N/A|
|modern|grader|`http://grader.mod.pccc`|N/A|N/A|
|modern|ubuntu|`ubuntu.mod.pccc:8888`|user|password|
|future|perfect dark|`perfectdark.fut.pccc:22`|jack.dark|password|
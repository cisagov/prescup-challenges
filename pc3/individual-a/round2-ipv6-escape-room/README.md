  # IPv6 Escape Room

  A disgruntled former network engineer broke local router configuration
  right before being fired and escorted off the premises by security. You
  lost (IPv6) connectivity from your desktop to a server located two
  Layer-3 routing hops away. Your job is to restore that connectivity,
  collecting credit tokens along the way.

  **NICE Work Roles:**

  - [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Infrastructure+Support+Specialist&id=All)
  - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Incident+Responder&id=All)

  **NICE Tasks:**

  - [T0041](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0041&description=All) - Coordinate and provide expert technical support to enterprise-wide cyber defense technicians to resolve cyber defense incidents.
  - [T0180](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0180&description=All) - Perform system administration on specialized cyber defense applications and systems (e.g., antivirus, audit and remediation) or Virtual Private Network (VPN) devices, to include installation, configuration, maintenance, backup, and restoration.

  ## IMPORTANT

  This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

  ## Background

  You are given access to a user desktop machine, `kali`, residing on a
  native IPv6 network segment, assigned the `2001:5::/64` network address.
  This machine is expected to reach a server, located two router hops away,
  on IPv6 address `2001:6::101`. The two routers in between the desktop and
  server are `r1` and `r2`, and their configuration has been maliciously
  modified by a disgruntled former network engineer, right before they were
  fired and escorted off the premises by security.

  ## Getting Started

  You will need to find a way to first ssh into `r1` (your default gateway)
  from the `kali` desktop machine. From there, you should be able to connect
  via ssh into `r2`. Examine the (vyos) router configurations, and restore
  connectivity from the desktop to the server at `2001:6::101`.

  ## Submission Format

  On each of the two routers, run `prescup-get-token` to obtain an 8-character
  token to be submitted for partial credit. Use `telnet` or `nc` from the `kali`
  machine to connect to the server (`2001:6::101`) on port `31337` for the
  third (and final) 8-character token.

  ## System Credentials

  | system  | username | password |
  | ------- | -------- | -------- |
  | kali    | user     | tartans  |
  | r1      | vyos     | vyos     |
  | r2      | vyos     | vyos     |
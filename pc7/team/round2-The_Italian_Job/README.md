# The Italian Job

"It is a work of genius. Just think of it. A city in chaos, a smash-and-grab raid, and four million dollars through a traffic jam." Hack into a traffic management center to set up a green-light getaway in this mix up of the 1969 and 2003 movies.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

"You want all greens? 'Cause, ah, 'cause you got 'em."

Brought on to the team for your notorious hacking skills, you've been tasked with ensuring a clean getaway for the main heist team. Of course, a green-on-green scenario is just movie magic thanks to the hardwired MMU installed in the cabinets, but you've devised a clever new plan. Instead, you'll be paving the way for an escape vehicle by making their route out of town hit all green lights.

Your team will start by breaking into the Traffic Management Center (TMC) with a bad USB drive. During recon, you recovered a trashed workstation that they had previously been using for logging traffic data picked up in the field; we've repaired it so you can investigate. A team member will drop the USB outside the TMC once you've figured out the payload.

Once in the TMC, you'll need to move laterally to the workstation they do their traffic updates on. Given that's on their internal network, we have no recon there.

With access to the update station, you'll be tampering with an update file. They've got scheduled updates for the controllers coming up, and those have to be done manually.

Finally, with access to the traffic controller, you'll need to hack into the web panel to change the signal timings. We need the drive straight down `5th street` to be all greens. It's a 10-minute drive, so make sure the greens last at least that long. We didn't synchronize our watches, so timing will be tight; make sure to minimize the time that the minor cross-streets and other lights stay green as well.

## Getting Started

Use the provided Kali machine to access the host `local-media.pccc`, which runs the same logging software as the real system. You can visit `http://challenge.pccc` to upload your bad USB files, trigger the TMC to start their updates, and to start the getaway.

## Tokens

There are four tokens to retrieve, formatted as `PCCC{string}`.

Grading is required. Visit `http://challenge.pccc` for Tokens 1, 3, and 4.

- Token 1: Break into the TMC's media workstation and find this token in `user`'s home directory.
    - You can upload your malicious USB files as a ZIP file at `http://challenge.pccc`
- Token 2: Find this token in `user`'s home directory after moving laterally from the media workstation to the update workstation.
- Token 3: Find this token in `/root` after gaining access to the network switch in the traffic cabinet.
    - You can trigger the TMC employees to load the update onto a USB and install it in the cabinet by visiting `http://challenge.pccc`.
- Token 4: Break into the traffic controller's web panel and change the signal timings so that `5th street` has at least 10 minutes of green, and the other lights have the shortest green time allowed.
    - You can trigger the getaway from `http://challenge.pccc`; if successful, the token will be provided on that site

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|
|local-media.pccc|user|password|
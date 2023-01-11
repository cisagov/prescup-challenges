# I Can't Believe It's Not Honey

Investigate and perform reconnaissance on a passing probe in order to gain intelligence and insight into the actions of an unknown race of space travelers.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-analyst)
- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/data-analyst)
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)

**NICE Tasks**

- [T0299](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0299) - Identify network mapping and operating system (OS) fingerprinting activities.
- [T0403](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0403) - Read, interpret, write, modify, and execute simple scripts (e.g., Perl, VBScript) on Windows and UNIX systems (e.g., those that perform tasks such as: parsing large data files, automating manual tasks, and fetching/processing remote data).
- [T0616](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0616) - Conduct network scouting and vulnerability analyses of systems within a network.

## Background

A probe has entered the star system. Command has approved a flyby to retrieve as much data as we can from the probe. The probe is believed to be of Vigil origin. This mysterious race of non-organic creatures regularly send probes through all known regions of space, but refuses to interact with the organic sentient races.

Scientists do not know much about the probe in question but have a few theories:

- The probe must have some sort of interactive web service for administration, though we expect the language used to be some sort of universal language, like binary, which would need to be converted.
- The probe obfuscates its running services and run honeypots in order to hide its data. Remote access is required to retrieve the data. Therefore, there must be ways to gain access.
- The probe uses common networking prototcols and broadcasts a service similar to DHCP that provide an address to your systems while on the same network.
- The probe contains encrypted messages sent and received by the Vigil. The Vigil seem to prefer the AES 256-bit CBC algorithm. Look for messages specifically containing the "VIGIL" marker to tag them for further analysis.
- The probe moves in an Archimedes spiral; its position can be calculated as `X = r x COS(Θ)`, `Y = r x SIN(Θ)`, and its movement is determined by the equation `r = a x Θ`, where the radius is measured in AU and Θ is measured in radians. 

## Main Objectives

The following ports should be scanned for services: 

`19,20,21,22,23,25,42,53,69,81,123,135,161,445,623,1025,1433,1723,1883,1900,2404,3306,5000,7634,8443,10001,11112,27017,50100,51884,61059,61093,61229,61468,61932,62427,62492,62585,62656,62921,63086,63216,63334,63408,63680,64294,64295,64297,64304`

Search for possible web services running on the probe, test them, and scan them for visible or potentially hidden information.

Search for interactive file transfer services that would allow you to retrieve the probe's data, like SSH and some form of FTP. Investigate and analyze any data recovered from the probe on these services, which we expect may be encrypted.

Detect and analyze any traffic coming from the probe itself while in proximity.

Understand where the probe has been and use this data to predict where it is headed next so we can send this tracking information to command. A table of possible destinations is listed below.


## Destinations List

| Destination | X | Y |
|-------------|---|---|
| Velorum-Suhail    | -3.743599 | 3.141253 |
| Arae-Cervantes    | -3.109576 | 2.177348 |
| Scorpi-Larawag    | -3.015441 | 1.740966 |
| Aquilae-Altair    | -4.290647 | 2.000762 |
| Arientis-Hamal    | -4.198587 | 1.528161 |
| Draconis-Kuma | -4.728833 | 1.267087 |
| Pegasi-Sadalbari  | -4.850492 | 0.855273 |
| Eridani-Ran   | -5.476866 | 0.479164 |
| Lyrae-Vega    | -4.572045 | -0.803175 |
| Ceti-Menkar   | -6.111487 | -0.534686 |


## Hints

Parts of this challenge will rely heavily on scripting to make the tasks easier and quicker.

The questions will guide your analysis and provide further hints as to what to look for.

## Challenge Questions

1. What is the page name that holds the secret information on the probe's website?
2. Which 3 files recovered from the zip files contain the "VIGIL" text marker? (order does not matter, though all three filenames must be present). The filename also matches the zip file that contained it.
3. Which of your system's ports are being scanned by the probe? (order does not matter, though all five ports must be present)
4. What is the next destination on the probe's journey (including any hyphens)?

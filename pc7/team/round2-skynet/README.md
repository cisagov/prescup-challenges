# Skynet

Parse a custom binary file format and perform geospatial analysis of drone flight paths.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T1607](https://niccs.cisa.gov/tools/nice-framework/): Recover information from forensic data sources

## Background

An enemy spy agency employs an advanced satellite surveillance system called `Skynet` that poses a serious threat to your operations.
In order to complete your missions successfully and covertly, you must avoid the watchful eyes of `Skynet`.
You have captured a binary file detailing drone flight paths, some of the drones belonging to your agency. 
Modify the binary and feed the tampered data to skynet in order to hide your drone operations.

## Getting Started

Use the provided kali machine to browse to `http://skynet`. Download the flight data and analyze the binary.
After modifying the binary, use the `Upload to Submit` button for grading.

## Questions

- Question 1 - Sort the drone names from A to Z and find the last drone in the list. Change this drone's name to `Jet Streamer`.
- Question 2 - Find the only drone that is not located within the US. Reduce the latitude and longitude of each coordinate on the flight path by `5`.
- Question 3 - Find the drone with the longest flight time. Add `3` seconds to the flight time between each coordinate in the drone's flight path.
- Question 4 - Find the drone with the longest flight path. Reverse the flight path so the last point on the flight path becomes the first point and vice versa. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|`http://skynet`|N/A|N/A|

# Silk Road 4.0

## Solution

Mass of data including GPS data files provided. Tasks will be to:

1. Analyze README and requirements file, decrypt and read clues for how to approach gpx data
2. requirements.txt is in morse code and defines python libraries players will need
3. README contains an encrypted string and the key which should provide teams with hints that the flag will have to do with known usernames of the silk road administrator
4. Parse and analyze gpx files in order to best understand what data is provided

Note that in the name of the gpx metadata, 12 files contain "frosty" one of the admin account usernames
Using gmplot and plotting these twelve files in the correct order will spell out JOSHUATERREY
Flag will be found as joshua-terrey-etc... in some other gpx file metadata

Another way to see which (12) files are the truly interesting ones is that all of the GPX data is for the European alps, the 12 files outside of this cluster, are the only files that are of interest (outside of the actual file that contains the key)

## Hints

1. requirements.txt file. In morse code, but once decoded, gives you all the python libraries needed in order to solve this challenge.

2. The readme file contains several hints to usernames that are associated with Ross Ulbricht (except the one you need to find in gpx files). It also contains an encrypted string and the key which should provide teams with hints that the flag will have to do with known usernames of the silk road administrator.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

<img src="../../../pc1-logo.png" height="250px">

# The Curious Case of the Matryoshka

## Solution

This challenge contains multiple levels.

##### Level 1

The zip file is named `Who Am I`. The password to the Level 1 zip file is the nickname from the Intelligence Report document. The hacker's nickname is `Warlock` which is the password for the first zip file.

##### Level 2

You must inspect the metadata info attached to each of the 6 to 7 images, hinted at by the name of the instructions file `You're so meta`. The Mario image is a red herring and will appear in all subsequent folders. You may use exiftool or an online source such as https://www.get-metadata.com/. The password is present in the `Profile Copyright` tag of the `Luigi's Mansion image`. The password is `2q89vzqrfova` and it will unlock the Level 2 zip file.

##### Level 3

You must understand that the timestamps in the `Password Table.csv` file are in Epoch time. There is a subtle reference to this in the name of the instructions file `The times we had were epic.rtf`. The suspect's birthday is also `January 1st, 1970`, which is when epoch time began. After converting the U.S. release date of Luigi's Mansion (`November 18, 2001`) from Level 2 to the corresponding Epoch time (`1006095155`), you should be able to find a similar/very close time in the csv file, since the exact time of day may differ. The corresponding password (`imevap4o18ej`) to this timestamp will unlock Level 3's zip file.

##### Level 4

You must understand that the numbers presented are Long/Lat coordinate pairs. You should look up all of these places in Google Maps or something similar. You should also reference the original intel report. Only 1 of the 10 locations is different than the others and the other 9 will match his dislikes, so intuitively, he would not want to meet there. The password will be the two-word capitalized name of the location (`Puerto Rico`) as it is pinned on Google Maps at the exact coordinates given. This will unlock Level 4's zip.

##### Level 5

You will need to reverse the `Caesar/ROT shift cipher` used to encode these 5 files. The shift value is always the inverse of the suspect's favorite number. Alternatively you could just use an online resource to shift all 26 permutations at once. The file with the password is `x2n0wuh9sue1.txt` and it has a `ROT shift of -7/19`. The password (`yaqitkcuyrgx`) found in the file will open the Level 5's zip file.

##### Level 6

You must hash the album cover image and use this hash value as the password to the final zip, Level 6. The player should note that the example hash value is 32 bits long and only try hashing algorithms that are 32 bit. MD5 or SHA-1 being the most common choices, MD5 will produce a matching value. The MD5 hash (`818532970e654e26d76e27858c508346`) of the album cover image is the password to the 6th and final zip file.

Final Flag file - There is no work to be done at this point. In the final zip is the flag file containing the exact flag for this challenge.


<br><br>

Flag - `We're leaving together, but still it's farewell`

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

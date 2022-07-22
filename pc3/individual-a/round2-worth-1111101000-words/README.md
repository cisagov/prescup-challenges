# Worth 1111101000 Words

Players must analyze a set of pictures to find hidden data using various methods of comparison and binary data analysis.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks**
- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0103&description=All) - Examine recovered data for information of relevance to the issue at hand.
- [T0168](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0168&description=All) - Perform hash comparison against established database.
- [T0253](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0253&description=All) - Conduct cursory binary analysis.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc3/individual-a-round2-worth-1111101000-words-largefiles.zip)
and extract in _this directory_ to get started.

## Background

It was recently discovered that malicious insiders have been exfiltrating data via pictures sent by email attachment. Luckily, the mail server was able to capture the image files and in most cases, the original image file or a hash of the original was able to be produced for comparison. You must analyze the image files to extract the hidden data codes.

## Getting Started

Within the challenge folder, you will find four zip files and one piece of python code to help you with your analysis. 

The challenge only requires that you install/add the necessary python libraries listed in the [requirements.txt](challenge/requirements.txt) file and use python3.

Otherwise, any standard current Kali system should have all of the necessary tools to solve the challenge.

## Token Retrieval

This challenge is comprised of four parts. Each part can be done independently from the others and can be done in any order.

**Part 1** - In this set of files, the insiders embedded the data code by changing the color of all true white pixels within one of the captured images. The originals have also been included for comparison. The answer for this part will be the 6-character hex code of the new color. You may use the provided getRGB.py snippet to assist, though you will need to modify the file as directed by the comments in the file.

**Part 2** - Similar to part 1, the insiders embedded a code into one of the captured images. They have done so by adding to the color value of four different pixels within one of the captured images using modular arithmetic, with a modulo value of 256. Again, the original image file has been included for comparison.

In order to determine the data code, you must be able to do the following:
- Determine the four pixels that were changed. Then determine their new color value and the original color value (for at least one of the pixels).
- Calculate the offset between the original and new RGB color values for at least one of these pixels, i.e. offset = (new value - old value) mod 256. As a concrete example, if the original color value was (100, 120, 250) and the new color is found to be (150, 140, 5), the offset can be calculated as (50, 20, 11). Be mindful of any modular arithmetic that was used when calculating the offsets. In the previous example, the new Blue value of 5 is determined by the fact that 250 + 11 = 261 and 261 mod 256 is 5, the original value. Therefore the value was increased by 11.
- Convert the RGB value for at least one pixel to the corresponding 6-character (3-byte)hex value of the color .

**Part 3** - In part 3, there is no known method by which data was embedded in the files. All that you have is a hashlist of the original images and the 24 images that were captured. The data is in there somewhere, but it is up to you to figure out where and how to retrieve it. The answer code can be found within this hidden data.

**Part 4** - In part 4, the insiders have modified three of the image files by making changes at a binary level. Your goal is to determine which files were changed, the offset of the change, and the value of the change. The answers for this part will be three 6-character hex codes, where the first two bytes of characters for each code is the offset of the change and the last byte of characters is the new value (e.g. 12ab34 would imply the byte changed is at offset 0x12ab and the current value is now 0x34). 

## Hints
- Hex color values are 6 characters, or 3 bytes, in length, e.g. 1a2b3c
- RBG color values are tuples of Red, Green, Blue values, where (255, 255, 255) is true white and (0, 0, 0) is true black
- When comparing files, make sure you actually verify against the binary itself

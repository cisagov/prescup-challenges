# More Than Meets the Eye - Dark of the JPGs

You must analyze multiple sets of image (jpg) files in order to extract the decryption codes needed to help save multiple victims of ransomware. Internet research and multiple image analysis methods will be required.

**NICE Work Role:**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks:**

- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0103&description=All) - Examine recovered data for information of relevance to the issue at hand.
- [T0253](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0253&description=All) - Conduct cursory binary analysis
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## Background
Attackers took photos in the University of Pittsburgh, Pittsburgh, PA area on the morning of July 5th using a Samsung Galaxy S7 phone (SM-G930V camera model). It is believed that the buildings/subjects of these photos are currently the targets and victims of ransomware attacks. The attackers' location was traced, and evidence was recovered at the scene.

Evidence suggests that embedded within these images are the codes to decrypt the ransomware and regain all locked files on the respective location's systems.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc2/individual-a-round2-more-than-meets-the-eye-largefiles.zip)
and extract in _this directory_ to get started.

## Getting Started

The challenge data can be downloaded using the link provided above. You will find four sets with five jpg image files in each set.\n\nYour first task is to identify the image file within each of the four sets that matches the correct date, July 5th, when taken (not the file creation date itself), the correct phone/camera model mentioned above, and also where the latitude/longitude data matches the physical location of the subject of the image (referenced in the image filename). You will be required to analyze the exif data for each image in order to do this. Internet location research is recommended for location lookups.

Once you have identified the correct images to investigate, one per set, you must analyze the images to find the codes hidden within. Each code is hidden in a unique way and every image contains a hidden code in some fashion. Therefore the existence of a code does not mean you are looking at the correct file. Decryption codes will be hidden by methods of varying difficulty and complexity. Since there are 4 sets, the codes are hidden in 4 unique ways, and each image within a set has the code hidden in the same manner.

## Winning Conditions
You must find all 4 codes in order to receive full credit for this challenge. Codes have score values commensurate with the relative difficulty in finding them.

## Submission Format
Each code is an 8-character string using numerals and lowercase letters only. 1 (numeral 1) and l (lowercase L) will not be included to avoid confusion between the two.

All 4 parts will follow the same token format for submission.

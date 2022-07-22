# Spies Like Us

Given a raw DD forensic image and two encrypted containers, find several pieces of information within the image to decrypt the containers. Use the forensic tools available to complete this team challenge.

**NICE Work Role:** 

- [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks:**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.
-[T0238](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Extract data using data carving techniques (e.g., Forensic Tool Kit [FTK], Foremost).
- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Perform file system forensic analysis.
- [T0289](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Utilize deployable forensics toolkit to support operations as necessary.
- [T0397](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Perform Windows registry analysis.

## IMPORTANT

This challenge is partially open sourced. An informational PDF file ([spies-like-us-info.pdf](./challenge/spies-like-us-info.pdf)) can be found within the [challenge folder](./challenge). This file and others were provided during the competition and can serve as a starting point if you wish to recreate the challenge yourself.


### Background

You are assisting federal law enforcement with an espionage investigation involving the suspected illegal sharing of highly classified information between a U.S. government contractor and a foreign intelligence service.


### Getting Started

Klaus Fuchs is a U.S. Government contractor suspected of exchanging classified material with a foreign intelligence service.  The FBI arrested Klaus Fuchs on espionage charges and imaged a suspicious virtual machine that Klaus used on his computer.  It is now up to you to locate the remaining information needed to further the investigation.

Klaus was last in contact with a foreign intelligence agent named Aldrich Ames, who provided Klaus with classified material stored within a hidden volume of a keyfile/password encrypted container named `OutdoorPics.zip`. The key-file to open `OutdoorPics.zip` is within an encrypted container named `VacationPics.zip`. You must decrypt the containers to access the classified material.

**NOTE:** The encrypted containers are available to you as separate evidence on the mounted DVD (D: drive) and are NOT part of the forensic image. Within the D: drive, you will also find instructions needed to decrypt the containers in `spies-like-us-info.pdf`. **Autopsy** and **Bulk Extractor** reports are already available within an `Image` folder on your VM Desktop to minimize the time it takes to analyze the forensic image. The forensic image for Klaus' computer is also present in the `Image` folder.

## Questions

1. What is the public IP address associated with an encrypted email sent from Aldrich to Klaus on `10 APR 20 at 14:59 CT`? 

2. What is the last write time (UTC) of the Local Area Connection* 2 interface as listed in the registry? 

3. What is the quote at the end of the encrypted email that Klaus received from Aldrich on `10 APR 20 at 14:59 CT`? 

4. What is the hashtag label listed on the file within the hidden container of `OutdoorPics.zip`? 

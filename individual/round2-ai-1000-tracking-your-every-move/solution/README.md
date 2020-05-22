<img src="../../../logo.png" height="250px">

# Tracking your every move

## Solution

Evidence from a MacBook is available for analysis. The first step is to realize what type of evidence it is –

* `Login-keychain.db` is the keychain file found in macOS that stores credentials for websites, servers, applications, etc. 
* The folder with 40 characters long hexadecimal name contains an iPhone backup. Examine the plist files present in the folder to determine the same.
* MacBook password

Apart from the three plist files and a database file present in the iPhone backup folder, there are several folders with files within them. The folders are named using the first two characters of the name of the files present within them. The name of the files is also 40 characters long hexadecimal values. On viewing the content of these files, you’ll notice that the text is all garbled. It is not in a human-readable format. Opening `manifest.db` file asks for a password, implying that this backup is encrypted with a user-defined password. 

There is a chance that the iPhone owner may have saved the iPhone backup password to the macOS keychain (`login-keychain.db`). You may use the `dumpkeychain.exe` application and try dumping the `login-keychain.db` file to see if that is the case. 

```
dumpkeychain.exe -u login-keychain.db "mhtYGV&8%" output.txt
```

Once you have the iOS backup password, you can decrypt the iPhone backup files using any of the free utilities available online. One such application is `PhoneRescue`. The `PhoneRescue` application unlocks/decrypts the iPhone backup files, and saves those at the default iPhone backup location. 

Once the iPhone backup files are unlocked/decrypted, you may either use a GUI tool at your disposal or manually analyze the files to find the answer. This guide provides a method to analyze the backup files manually.

The mapping between the 40 characters long file name and the actual file it represents is present in `manifest.db` file.

You'll need a plist viewer and `DB Browser for SQLite` or a similar application for analyzing plist files and databases respectively.

Now to answer the question, let us first find the date for the last backup. This information is present in the `info.plist` file (`Last Backup Date` is the key). It will be a reference point to answering when did the owner most recently eat Latin/Mexican food. 

The next step is to look through the list of `Installed Applications` in `info.plist` file, and determine the possible apps used for finding food/restaurants in the nearby area (Uber Eats, Yelp, Grubhub, etc.). Analyze all these apps one by one. You’ll find the answer in the `Yelp` app. 

To find all the files associated with the Yelp app, open `manifest.db` file, and filter for `yelp` in the `domain` column. Review `business.sqlite` database file. The hexadecimal file name is `149f81ed87ff080fd6c03692f340654a5f34947d`. This file contains `ZCHECKIN` table that contains the Yelp check-in data. Extract GPS coordinates and timestamp information from that table. Use online resources to convert latitude longitude data to address, and timestamp information (Apple Cocoa Core Data timestamp format) to a human-readable date.

<img src="screenshot/Picture1.png">

<br><br>

Flag - `02132020_20105`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
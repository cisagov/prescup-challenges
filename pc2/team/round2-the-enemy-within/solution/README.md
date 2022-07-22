# The Enemy Within Solution

# Steps to Solve

1. Copy the executable from the mounted disc to the desktop.
2. Run it and observe that a blank console window opens.
3. Open Task Manager and run again. Observe that under the process tree associated with this executable, there is a
   second executable running with a random-looking name, located in `C:\Users\flare\`.
4. Locate this secondary executable on the disk.
5. Open ProcMon (in the `FLARE\Utilities\` folder on the Desktop).
6. In the Filter Menu (three to the right of File), select the Filter option.
7. Set the match conditions to `Process Name`, `is not`, enter the name of the executable you found (just the file
   name), and then `Exclude`.
8. Run the malware program and wait until it completes.
9. There should be over 200,000 entries listed in ProcMon now, most of which are file operations.
10. Near the end of the list, there are a lot of `WriteFile` operations to a file in `C:\Users\flare\Music\` with a
    random-looking name.
11. Navigate to this folder, right click on the file (or one such file, if you've run the program multiple times), and
    click the `detect it easy` entry to determine its file type. Observe that it's a zip file.
12. Open the file in 7-zip or any other tool that can open zip files. Extract the `flag.txt` file.
13. Open `flag.txt` to get your submission token.

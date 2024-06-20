File Locations
1. You have been given the com.companyname.androidprotektor.apk file along with some of the source code that we were able to recover.
2. The com.companyname.androidprotektor.apk file is in the /home/user/Documents directory. 
3. The source code files are located in the /home/user/Documents/Code directory.

--------------------------------------------------------------------------------------------------------------------------------------

Software
In addition to the tools provided in our Kali Linux VM, we have installed Android Studio 2022 and jadx v1.4.7. 
Instructions for running these applications are included below.

1. Android Studio 2022
   Open a terminal and run the following command:
   sudo ./Desktop/android-studio/bin/studio.sh

   You can run the com.companyname.androidprotektor.apk using the Pixel 3 emulator that is installed with Android Studio.
   Open Device Manager
   Select the Pixel_3a_API_34_extension_level_7_x86_64 Device and click the play button.
   It will take a few minutes for the emulator to start.
   Install the com.companyname.androidprotektor.apk file by dragging it onto the screen on the running device.
   Run the com.companyname.androidprotektor.apk that you installed on the device. It will appear as AndroidProtektor in the Apps list.

   **************************************************
   If the AndroidProtektor app fails to install you can simply drag it back onto the emulator. You may need to repeat this step a few times.

   If you receive messages from the Android emulator such as . . . 
   "System UI isn't responding" or "Process system isn't responding", you should choose the 'Close app' option.   

   The app is known to be unstable and one or more restarts of the app and/or the emulator may be required while you examine the running APK and it's behavior.
   **************************************************

2. jadx-1.4.7
   Open a terminal and run the following command:
   sudo ./Desktop/jadx-1.4.7/bin/jadx-gui


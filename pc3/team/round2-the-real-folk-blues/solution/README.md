# The Real Folk Blues Solution

## Step by Step

# Finding the program causing the BSOD
 1. Boot into the WinXPE Iso on the BSODing machine by hitting ESC and selecting CD
 2. Launch windbg.exe and open the minidump file in the mounted OS (`C:\Windows\Minidump`)
 3. Make sure you use the correct symbols! (`C:\symbols`)
 4. Scroll down to find BSOD.exe causing the BSOD
 5. Find the BSOD.exe shortcut in `C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
 6. Get the MD5 hash of BSOD.exe located in `C:\Program Files\FreeShows4U\FreeShowsInstaller\BSOD.exe`
 7. 
 
 ```powershell
 Get-FileHash "C:\Program Files\FreeShows4U\FreeShowsInstaller\BSOD.exe" -Algorithm MD5
 ```

 8. Delete or move the `BSOD.exe` shortcut out of the startup folder
 9. Submit the token at challenge.us after you boot into `C:\Windows`

# Finding the website of the installer
 1. Log back into the machine
 2. Run strings on the installer located on the Desktop
 3. Find the website `www.freeshows.com`
 4. Visit the website, get the flag

# Finding the registry entry
 1. You can find this multiple ways
 2. Easiest way is to find the Author of the installer, FreeShows4U in the metadata of the installer
 3. Go to `HKCU\Software\FreeShows4U\private_exe`
 4. Find the token entry

# Interacting with TrollSoftware
 1. If you try to run the program, it will fail
 2. By just using `www.freeshows.com`, the program will run and try to connect
 3. Notice that it will either freeze or not log you in
 4. You have to edit the registry key `seeyouinspace` with the value `$wordfishII` found in the exe TrollSoftware
   - You can investigate using dnSpy in the Tools directory on the desktop to look at the source
 5. The server will reply with the last token

# Finding Footprints Solution

This challenge involves analyzing disk images and finding key information regarding an attack that is going to occur. The information that is needed to pass is the name of the external person helping/planning the attack, the name of the person they are targeting within the organization, the IP address of the machine they are targeting and the date on which the attack is set to

## Hans

You'll need to boot into the VM and do some analyzing. From here you will see that Virtualbox has been downloaded and been used by the host. Boot it up and see that there are two VM's in `C:\users\flare\VirtualBox VMs\`.

Boot the Workstation VM. Check out the file system and you'll see that nothing is really out of place but there is a directory named "Hans" that cant be accessed.

From here, you should think to check the second VM. Boot up the Gateway VM.

After some more analyzing of files, you'll find that there is one hidden file named ".backup" that the user Hans has created and edited recently. 

View the file and you will see the message >Hans, don’t forget about the mail – *NAME*

This is a hint at what the password is

go back to the workstation VM and log in as Hans with the password **NAME**

The message is also a hint at where the files are in the Hans directory, so maneuver to the *Mail* directory and you will find more messages.

In there the user will mention the external threats last name, >Hook
, and also hint at how he is **Downloading** files from him.

You should then go and check out the Download folder that is used for files from the Tor Browser.

Here you will find a file which provides the first name of the external person.

The flag is the person's initials.

## Karl

If you look in the downloads folder of the Windows machine, you'll see that a OVA has been downloaded, this should point you to VirtualBox again

Boot up the Workstation VM again and run `history`. Here you will see there is some data left

You'll see that commands were ran to delete a directory named >Herman

You can attempt to retrieve the info using any programs available on the machine

The main method of retrieving it is realizing that there is a saved snapshot in VirtualBox from a previous state.

Restore that snapshot and boot back into the VM.

There will be a directory there, go in and it will look normal to basic commands. You must look for hidden files/directories as well

You'll find a hidden directory, move into it.

You will find files here that contain information on their target.

The flag is the target's initials.

## Theo

Log into the Theo Windows machine and you should see immediately that there are files in the recycle bin. These are VirtualBox files

You should move these files then to the directory `C:\users\flare\VirtualBox VMs\Tails\`

From here, you need to open the .vbox file (double-click, or right-click and open)

This will show/launch a VM in VirtualBox that has a saved state which was not there previously.

Launch the VM and then run `history`.

You will see that files were moved to the `/usr/games` directory and the permissions were altered using the root account, you will need to find the root password.

The thought should be to check tor downloads, and by doing so you will find a note in the Tor-browser directory from the external user explaining how he set up the root account with the password >m3mory

run a command using `sudo` to then access the files previously locked (can be chmod, cat, any method to view files)

You will find files containing an arp scan and two nmap scans of machines.

Looking at them, only one has information that matches other data found in other machines, (explains that target is windows 10)

The flag is the IP.

## Eddie

By now, it should be apparent that VirtualBox is something to check, so start by opening it

Run the Tails VM that is available in `C:\users\flare\VirtualBox VMs\Tails\`

Do a scan and you'll find that there is nothing really out of the ordinary. Next would be to check the settings of the VM.

You'll find that there is a Shared folder between the host windows machine and the Tails OS. 

You will then find that the `/mnt` directory in Tails is linked to the `C:\ProgramData\VirtualBox\logs\` directory in Windows

Check the files in there and the user will explain how he is using this directory to work/save the code he has been working on for the attack since everything gets wiped when Tails shuts down as it doesn't save any data naturally.

If you look at the `logic.py` file, you will see that he has code he's been working on and its set to run on a certain date.

the flag is the date.
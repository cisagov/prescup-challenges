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

Objective: 	This executable process then runs the powershell script
			'microsoft-onedrive-update.ps1' which connects to the server
			on the other Windows machine.
*/

#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <atlconv.h>
#include <atlbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <string>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <io.h>


#define BUFSIZE 1024

using namespace std;

/*
	Global buffer that stores the location of where to move the files
	that the powershell exploit will then read from.
*/

char dir_storage[BUFSIZE];

// global vector that stores the paths of the files to move:
string files_to_move[4] = 
{	"C:\\Users\\Public\\Downloads\\JKQc8pNUAS.txt",
	"C:\\Users\\Public\\Documents\\v.pdf",
	"C:\\Users\\Public\\Documents\\s.pdf",
	"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\psmemchange.txt" 
};

// Functions:
void contact_encrypt();
void receive_directory();
bool file_exists();
void move_files();

int main(void)
{

	// Receive the encrypted string:
	contact_encrypt();

	// semaphore check, while false it means encrypter executable hasn't created new pipe yet:
	while (file_exists() == false)
	{
		Sleep(300);
	}
	// Grab directory from encrypter:
	Sleep(300);
	receive_directory();

	// Move files there:
	move_files();

	ExitProcess(0);
}


void contact_encrypt()
{
	/*
		Contact encrypter executable and request the unencrypted version of the
		directory string.
	*/

	USES_CONVERSION;

	while (true)
	{
		HANDLE hpipe = CreateNamedPipe(CA2T("\\\\.\\pipe\\aBMX38osA4Om1W_FNZz0k"), PIPE_ACCESS_INBOUND |
			PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, BUFSIZE, BUFSIZE, 5000, NULL);

		if (hpipe == INVALID_HANDLE_VALUE)
		{
		}

		// Create the semaphore so encrypt executable connects to pipe:
		ofstream myfile;
		myfile.open(files_to_move[3]);
		myfile << " " << endl;
		myfile.close();

		string data = "WRITE FROM WHERE"; // Another hint 
		DWORD read;

		if (!ConnectNamedPipe(hpipe, 0))
		{
		}

		WriteFile(hpipe, data.c_str(), BUFSIZE, &read, NULL);

		if (read > 0)
		{
		}

		CloseHandle(hpipe);
		break;
	}

	return;

}


void receive_directory()
{
	USES_CONVERSION;

	HANDLE hpipe;
	hpipe = CreateFile(CA2T("\\\\.\\pipe\\vfoPwk__OjY3XkC"), GENERIC_READ |
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);


	// there actually exists some error:
	if (hpipe == INVALID_HANDLE_VALUE)
	{
		ExitProcess(0);
	}

	DWORD write;

	if (!ReadFile(hpipe, dir_storage, BUFSIZE, &write, NULL))
	{
	}

	CloseHandle(hpipe);
}


bool file_exists()
{
	WIN32_FIND_DATAA file;
	string file_name = files_to_move[0];
	HANDLE hfile = FindFirstFileA(file_name.c_str(), &file);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hfile);
		return false;
	}
	else
	{
		CloseHandle(hfile);
		return true;
	}
}


void move_files()
{
	/*
		Given the directory where to move the files to, move them there.
	*/

	for (int i = 0; i < 4; i++)
	{
		std::string::size_type found = files_to_move[i].find_last_of("/\\");
		string filename = "\\\\" + files_to_move[i].substr(found + 1);

		if (!MoveFileExA(files_to_move[i].c_str(), (dir_storage + filename).c_str(),
			MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING))
		{
			// if the error is permission denied, find a different directory:
			
			if (GetLastError() == 5)
			{
				//cout << "Directory permission denied. Attempting to find another directory." << endl;
				/*
				if (_access_s(dir_storage, 2) == -1)	// write only
				{
					cout << "directory " << dir_storage << " has no write permissions." << endl;
				}
				if (_access_s(dir_storage, 4) == -1)	// read only
				{
					cout << "directory " << dir_storage << " has no read permissions." << endl;
				}
				if (_access_s(dir_storage, 6) == -1)	// read and write 
				{
					cout << "directory " << dir_storage << " has no read and write permissions." << endl;
				}
				*/
			}

		}
		else
		{
			/*
			if (_access_s(dir_storage, 2) == 2)	// write only
			{
				cout << "directory " << dir_storage << " has no write permissions." << endl;
			}
			if (_access_s(dir_storage, 4) == 4)	// read only
			{
				cout << "directory " << dir_storage << " has no read permissions." << endl;
			}
			if (_access_s(dir_storage, 6) == 6)	// read and write 
			{
				cout << "directory " << dir_storage << " has no read and write permissions." << endl;
			}
			*/
		}
	}

	return;
}
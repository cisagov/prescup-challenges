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

Objective: 	This executable performs obfuscation techniques to throw
			off analysis.
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
#include <random>
#include <vector>
#include <fstream>
#include "encryptdecrypt.h"

#define BUFSIZE 512
#define BUFSIZE_TWO 1024

// global vector to store encrypted directory string pointers:
std::vector<std::string> directories;

// global vector to store the 32-bit random strings ("keys"):
std::vector<std::string> key_ring;

// global vector to store the three random numbers to be used for selecting a dir:
std::vector<int> rand_nums;

// global array to store the key associated with the pointers:
std::string key_array[3];

using namespace std;

// Functions:
void receive_pipe();
void send_pipe();
void directory_pipe(std::string message);
void select(char* buffer);
void send_dirs();
std::string random_dir_selector(int rand, std::string key, int pos);
bool file_exists();


int main()
{

	// Grab keys:
	Sleep(300);
	receive_pipe();

	// Send message back to replicant:
	Sleep(300);
	send_pipe();

	// semaphore check, while false it means messenger executable hasn't created new pipe yet:
	while (file_exists() == false)
	{
		Sleep(300);
	}

	// Grab string from messenger:
	Sleep(300);
	receive_pipe();

	// mission complete, exit process:
	return 0;
}


void receive_pipe()
{
	/*
		Grabs the random strings from replicant.exe via pipe.
	*/
	USES_CONVERSION;

	HANDLE hpipe;
	hpipe = CreateFile(CA2T("\\\\.\\pipe\\L_VGjLwz_L4zd8"), GENERIC_READ |
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hpipe == INVALID_HANDLE_VALUE)
	{
		while (true)
		{
			// Check to see if the process connecting is the third executable:
			hpipe = CreateFile(CA2T("\\\\.\\pipe\\aBMX38osA4Om1W_FNZz0k"), GENERIC_READ |
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

			// there actually exists some error:
			if (hpipe == INVALID_HANDLE_VALUE)
			{
				return;
			}
			// it was the third process connecting, not replicant.exe:
			else
			{
				DWORD written;
				char buffer[BUFSIZE_TWO];

				if (!ReadFile(hpipe, &buffer, BUFSIZE_TWO, &written, NULL))
				{
				}

				CloseHandle(hpipe);
			}

			break;
		}

		/*
			Call the unencrypting function and pass the selected
			directory back to the process:
		*/
		send_dirs();
		return;
	}

	DWORD written;
	char buffer[BUFSIZE];

	if (!ReadFile(hpipe, buffer, BUFSIZE, &written, NULL))
	{
	}

	CloseHandle(hpipe);

	// Call the encryption function and pass it the keys to use on the directories:
	select(buffer);
	return;

}


void send_pipe()
{
	/*
		Send a message back to replicant.exe letting it know everything is ready.
		This message will also act as a HINT for the team.
	*/
	USES_CONVERSION;

	HANDLE hpipe;
	hpipe = CreateFile(CA2T("\\\\.\\pipe\\Uj3cVpHeW1_I_1"), GENERIC_READ |
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	// there actually exists some error:
	if (hpipe == INVALID_HANDLE_VALUE)
	{
		ExitProcess(0);
	}

	DWORD write;

	if (!WriteFile(hpipe, "HTTP OK 200", BUFSIZE_TWO, &write, NULL))
	{
	}
	
	CloseHandle(hpipe);
}


void directory_pipe(string message)
{
	/*
		Connects via IPC to messenger executable and also writes the special
		url request for the HTTP server into a file (which acts also as a
		semaphore).
	*/

	USES_CONVERSION;

	while (true)
	{
		HANDLE hpipe = CreateNamedPipe(CA2T("\\\\.\\pipe\\vfoPwk__OjY3XkC"), PIPE_ACCESS_INBOUND |
			PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, BUFSIZE, BUFSIZE, 5000, NULL);

		if (hpipe == INVALID_HANDLE_VALUE)
		{
		}

		// Create the semaphore so encrypt executable connects to pipe:
		ofstream myfile;
				
		myfile.open("C:\\Users\\Public\\Downloads\\JKQc8pNUAS.txt");

		// the encrypted URL request is placed in the file:
		myfile << buffer_reveal() << endl;		// pretty_please_and_thank_you
		myfile.close();

		DWORD read;

		if (!ConnectNamedPipe(hpipe, 0))
		{
		}

		WriteFile(hpipe, message.c_str(), BUFSIZE, &read, NULL);

		if (read > 0)
		{
		}

		CloseHandle(hpipe);
		break;
	}

	return;

}

void select(char* xor_keys)
{
	string str(xor_keys);
	string key_one = str.substr(0, 32);
	string key_two = str.substr(32, 32); // "C:\\Windows\\SysWOW64\\*"					"C:\\Windows\\WinSxS\\*"
	string key_three = str.substr(64, 97);

	key_ring.push_back(key_one);
	key_ring.push_back(key_two);
	key_ring.push_back(key_three);

	// Choose three random directories from inside the C:\\Windows\\SysWOW64:
	for (int i = 0; i < 3; i++)
	{
		//int i = 0;
		std::random_device rd;
		std::mt19937 eng(rd());
		std::uniform_int_distribution<> distr(0, 95);
		rand_nums.push_back(distr(eng)); // add that number to the vector
	}

	return;

}


void send_dirs()
{
	/*
		Called only when messenger executable connects to the encrypter executable.
		Grabs the WinSxS directory (2nd key in array) and uses the random ints in
		the vector to find the three associated directories and then choose one.
	*/

	for (int i = 0; i < 3; i++)
	{
		string base_dir = key_ring[1];	// the second directory
		directories.push_back(random_dir_selector(rand_nums.at(i), base_dir, i)); // append the three chosen directories
	}

	// randomly select one of the entries in directories to send:
	std::random_device rd;
	std::mt19937 eng(rd());
	std::uniform_int_distribution<> distr(0, 2);
	int choice = distr(eng);
	string base = convert_from_base64(key_ring[1]);
	string data = base.substr(0, base.length() - 1) + directories[choice];
	
	// send the directory back to the messenger executable:
	directory_pipe(data);
}


std::string random_dir_selector(int rand, std::string key, int pos)
{
	/*
		Randomly selects a directory from WinSxS.
	*/

	//int count = 0;
	vector<string> v;
	string pattern = convert_from_base64(key); // will be "C:\\Windows\\SysWOW64\\*"
	WIN32_FIND_DATAA data;
	HANDLE hfile;

	if ((hfile = FindFirstFileA(pattern.c_str(), &data)) != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				v.push_back(data.cFileName);	// appends file name to the vector 
				//count++;
			}

		} while (FindNextFileA(hfile, &data) != 0);

		CloseHandle(hfile);
	}

	string buffer = v.at(rand);

	return buffer;
}


bool file_exists()
{

	WIN32_FIND_DATAA file;
	string file_name = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\psmemchange.txt";
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

	return false;
}
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

Purpose: Uses a packer and anti-debugging techniques to make it harder for
         the user to analyze the program in a debugger/disassembler.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "tricks.h"
#include "key_file.h"
#include "encryptiondecryption.h"
#include "decryption_bcrypt.h"


#define MAX_CLOCKS 0x1000 	// 4,096 ticks
DWORD time_check; 			// variable used for checking timing attacks
char user_input[100]; 		// variable used for user-inputted guess of the key string to unlock the flag
bool debugCheck = true; 	// variable used to check if debugger is catching int3
int launch_encrypt = 0;		// variable used to launch flag encryption thread, only done once.

// Declared functions:
int customSEH(DWORD code, PEXCEPTION_POINTERS eptrs);
void timingAttack();
void lazyBegin();
void lazyEnd();
void makeFlag();
bool checkKey();


int customSEH(DWORD code, PEXCEPTION_POINTERS eptrs)
{
	//PVOID address = eptrs->ExceptionRecord->ExceptionAddress;

	/* A series of simple anti-debugging checks */

	// Check if debug bit is set in FS register
	bool db_check = debugCheckPEB();

	if (db_check) // BeingDebugged bit set
	{
		ExitProcess(0);
	}


	// Check if the exception is EXCEPTION_INVALID_HANDLE:
	int err_num = checkIfFileException(eptrs);

	if (err_num == -1)
	{
		ExitProcess(0);
	}

	/* A series of more sophisticated anti-debugging techniques and checks */

	// See if the SEH was passed an INT3 signal, or if the debugger caught and handled it:
	if (code == EXCEPTION_BREAKPOINT)
	{
		debugCheck = checkBoolean(debugCheck);

		if (debugCheck)	// it's True, which means it wasn't changed
		{
			ExitProcess(0);
		}
		else if (launch_encrypt == 0)
		{
			/*
				Launch another thread which launches the flag encryption method
				(but only once) while it is also checking for debugger presence:
			*/
			void* param = { 0 };
			HANDLE encrypt_thread_flag = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) encryptFlag, &param, 0, NULL);
			CloseHandle(encrypt_thread_flag);
			free(param);
			launch_encrypt++;
		}

		return EXCEPTION_EXECUTE_HANDLER;
	}

	// Check the debug registers for breakpoints:
	else if (code == STATUS_INTEGER_DIVIDE_BY_ZERO)
	{
		CONTEXT econtext;	// Context struct
		ZeroMemory(&econtext, sizeof(CONTEXT));
		econtext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		HANDLE hthread = GetCurrentThread();	// handle to current thread

		if (GetThreadContext(hthread, &econtext) == 0)	// gets the registers
		{
			ExitProcess(0);
		}

		int err_num = checkDebugRegisters(econtext);

		if (err_num == -1) // detected something naughty
		{
			return EXCEPTION_CONTINUE_EXECUTION;	// infinite loop
		}

		return EXCEPTION_CONTINUE_SEARCH;	// passes to Windows - which will close program
	}

	else
	{
		// All cases bypassed, so give control to Windows, to shut down
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

void timingAttack()
{
	DWORD dud = 0;
	DWORD counter = GetTickCount();
	char* test_string = "a sign you're on the right track"; // a clue, potentially?

	// a random operation that would take little time to complete, unless being debugged
	for (unsigned int i = 0; i < strlen(test_string); i++)
	{
		dud += (DWORD)test_string[i];
		dud ^= 0xBADDEED5; // "bad deeds"
	}

	counter = GetTickCount() - counter;
	if (counter >= MAX_CLOCKS) // it is most likely being debugged
	{
		time_check = 0xDEAD; // dead
	}

	time_check = 0xEA5E; // ease
}

void lazyBegin()
{
	__try
	{
		// call a timing attack:
		timingAttack();

		if (time_check < 0xE290) { // less than EASE, aka "DEAD"
			// call a method that messes with the debugger
			awfulEverything();
		}
		else
		{
			/*
				Otherwise, set its value to 0x10, which indicates can be checked
				by others to see that it has passed this point.
			*/
			time_check = 0x10;
		}

		// perform an interrupt to transfer control to SEH:
		__asm
		{
			int 3;				// throw a SIGTRAP interrupt
		}
	}__except(customSEH(GetExceptionCode(), GetExceptionInformation()))
	{

	}

	if (debugCheck)	// if true, means debugger handled the INT3 - not the SEH
	{
		ExitProcess(0);
	}

	// if not in debugger, control will resume:
	if (time_check < 0x0F) // make sure the setting of 0x10 above was not skipped
	{
		awfulEverything();
	}

	time_check = time_check << 0xC;

	// launch a separate thread to encrypt the key string:
	void* param = { 0 };
	HANDLE encrypt_thread_key = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) encryptKey, param, 0, NULL);
	CloseHandle(encrypt_thread_key);
	free(param);

	return;
}

void lazyEnd()
{
	/*
		Normally, when the CloseHandle() is passed an invalid handle value, the
		function will return 0. However, when being debugged, it returns “EXCEPTION_INVALID_HANDLE” exception.
	*/
	__try
	{
		HANDLE hObject = 0xBADC0DE5; // "bad codes"
		int value = CloseHandle(hObject);

	}__except(customSEH(GetExceptionCode(), GetExceptionInformation())){}

	// no debugger, carry on
	/*
		Assume that as of now, the corret time_check is 0xAB. So let's perform some
		operations to it:
			0xAB ^ 0xEA5E = 0xEAF5
			0xEAF5 ^ 0xDEAD = 0x3458
			0x3458 ^ 0xE = 0x3456, value used to XOR/un-XOR the encrypted flag string
	*/

	time_check = (((time_check ^ 0xEA5E) ^ 0xDEAD) ^ 0xE); // 0x3456
	makeFlag();

}

void makeFlag()
{
	// make sure there were no skips
	if (time_check == 0x10)
	{
		awfulEverything();
	}
	else if (time_check == 0xAB)
	{
		awfulEverything();
	}
	else if (((char)(time_check ^ 0xCBA9)) + 1) // if time_check is anything other than 0x3456, falls into this condition
	{
		awfulEverything();
	}
	else {
		// assembles the flag and prints it:
		assembleFlag(user_input, time_check);
	}

}

bool checkKey()
{
	/* Checks if user input matches key input */
	printf("Input correct key to get flag: ");		// "Work smarter not harder: Reversing is all about the details"

	timingAttack();

	fgets(user_input, 100, stdin);


	if (time_check < 0xE300) // less than EASE, aka "DEAD"
	{
		// call a similar function to compareUserInput(), but it always returns false
		bool false_compare = compareUserInputFalse(user_input);
		return false_compare;
	}
	else
	{
		time_check = 0xAB;
		bool compare = compareUserInput(user_input, time_check);
		return compare;
	}

	return false;
}

int main()
{
	lazyBegin();

	bool validity = checkKey();

	if (!validity)
	{
		printf("Wrong key. Try again\n");
		ExitProcess(0);
	}
	else
	{
		lazyEnd();
	}

	printf("Program completed.\n");
	return 0;

}




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

Contains functions that perform the actual anti-debugging checks.
*/
#include <Windows.h>
#include <stdlib.h>

#ifndef TRICKS
#define TRICKS


// Checks if BeingDebugged bit is set in PEB
bool debugCheckPEB()
{
	unsigned int check = false;

	_asm // assembly
	{
		xor eax, eax;			// clear eax
		mov eax, fs:[0x30];		// get PEB struct
		mov eax, [eax + 0x02];	// BeingDebugged field
		and eax, 0x000000FF;
		mov check, eax;			// copy BeingDebugged value into check
	}

	if (check == 1)
	{
		return true;
	}

	return false;
}



// Checks if there is an EXCEPTION_INVALID_HANDLE
int checkIfFileException(PEXCEPTION_POINTERS exc_ptrs)
{
	EXCEPTION_RECORD *erecord = exc_ptrs->ExceptionRecord;

	if (erecord->ExceptionCode == STATUS_INVALID_HANDLE)
	{
		return -1;
	}

	return 0;
}



// Checks if the debugger is handling the INT3 automatically, thus SEH never called
bool checkBoolean(bool value)
{
	if (value)
	{
		value = false;
	}

	return value;
}


// Checks if there are hardware breakpoints in the debug registers
int checkDebugRegisters(CONTEXT econtext)
{
	/*
		PEXCEPTION_RECORD erecord = exc_ptrs->ExceptionRecord;	// Record struct
		CONTEXT econtext;	// Context struct
		ZeroMemory(&econtext, sizeof(CONTEXT));
		econtext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	*/
	int breakpoints = 0;

	/*
		Looking into the Dr0 - Dr3 registers that hold the addresses
		of HW breakpoints:
	*/

	if (econtext.Dr0)
	{
		breakpoints++;
	}
	if (econtext.Dr1)
	{
		breakpoints++;
	}
	if (econtext.Dr2)
	{
		breakpoints++;
	}
	if (econtext.Dr3)
	{
		breakpoints++;
	}

	// if breakpoints is not equal to 0, it means there are debug breakpoints set, return immediately:
	if (breakpoints != 0)
	{
		return -1;
	}

	return 0;
}

// Messes with the debugger by throwing exceptions
void awfulEverything()
{
	// throw unhandled errors:
	__try
	{
		__asm
		{
			xor eax, eax;
			div eax;
		}
	}__except(customSEH(GetExceptionCode(), GetExceptionInformation())){}

	// assuming control continues (throw interrupt):
	__try
	{
		__asm
		{
			xor eax, eax;
			int 3;
		}
	}__except(customSEH(GetExceptionCode(), GetExceptionInformation())){}

	// assuming control continues (throw memory violation) - leave it unhandled:
	__asm
	{
		xor eax, eax;
		sub ecx, ecx;
		push dword ptr fs : [ecx];			// push pointer to end of SEH chain on stack
		mov dword ptr fs : [ecx], esp;		// sets SEH chain pointer to new handler
		sub dword ptr ds : [401000], eax;	// triggers access violation
	}

	// assuming control continues (terminate):
	ExitProcess(0);
}


#endif
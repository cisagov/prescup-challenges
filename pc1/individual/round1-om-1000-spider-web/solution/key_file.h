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
*/

#include "encryptiondecryption.h"
#include "decryption_bcrypt.h"


#define FAKE_KEY "PFLAG{Would_it_really_be_so_easy_?}"

#ifndef KEY
#define KEY

// Declared functions:
unsigned char* getKey(DWORD time_check);
char* getFalseKey();
bool compareUserInputFalse(char* userInput);
bool compareUserInput(char* userInput, DWORD time_check);
void assembleFlag(char* user_guess, DWORD time_seed);

// returns the unencrypted key
unsigned char* getKey(DWORD time_check)
{
	int size = ((time_check & 96) ^ 27);	// 59
	unsigned char* total_key = decryptKey(time_check);	// AB
	unsigned char* key = (unsigned char*) malloc(sizeof(unsigned char) * size);

	for (int i = 0; i < size; i++)
	{
		key[i] = total_key[i];
	}

	return key;
}


// grabs the fake key stand-in
char* getFalseKey()
{
	return FAKE_KEY;
}


// a fake function to compare user's input with a false key string
bool compareUserInputFalse(char* userInput)
{
	char* fake_key = getFalseKey(); // fake key

	for (int i = 0; i < (strlen(userInput) - 1); i++)
	{
		if ((strlen(userInput) - 1) == strlen(fake_key))
		{
			if (userInput[i] == fake_key[i])
			{
				continue;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	return false;
}


// compares user's input of the key with the actual, unencrypted key string
bool compareUserInput(char* userInput, DWORD time_check)
{
	int length = ((time_check & 96) ^ 27);	// makes the value 59

	// comparison of actual, unencrypted string:
	if ((strlen(userInput) - 1) != length)
	{
		return false;
	}
	else
	{
		__try
		{
			bool status;
			if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &status))
			{
				if (status)	// debugger present
				{
					__asm
					{
						xor eax, eax;
						div eax;
					}
				}
				else	// debugger not present
				{
					char* key = getKey(time_check);	// grabs unencrypted key

					for (int i = 0; i < length; i++)
					{
						if (userInput[i] == key[i])
						{
							continue;
						}
						else
						{
							return false;
						}
					}

					return true;
				}
			}

		}__except(customSEH(GetExceptionCode(), GetExceptionInformation())){}
	}
	return false;
}


// makes and prints the flag
void assembleFlag(char* user_guess, DWORD time_seed)
{
	// check the time_seed is 0x3456:
	if (((char)(time_seed ^ 0xCBA9)) + 1) // if time_check is anything other than 0x3456, falls into this condition
	{
		__asm
		{
			xor eax, eax;
			div eax;	// throw unhandled exception
		}
		awfulEverything();
	}
	else
	{
		// assemble and print the flag:
		unsigned char* unenc_flag = decryptFlag(time_seed);

		// prints the flag: pcupCTF{details_make_perfection_and_perfection_is_detail}
		printf("%s\n", unenc_flag);
	}
}

#endif
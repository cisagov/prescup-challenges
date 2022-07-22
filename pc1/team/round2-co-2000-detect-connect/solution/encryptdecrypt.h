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

#include <Windows.h>
#include <string>
#include <bitset>

#pragma comment(lib, "crypt32.lib")

#ifndef SYMBOL3
#define SYMBOL3

#define BUFSIZE_TWO 1024

// global vector to store unencrypted Base64 directories string pointers:
std::vector<std::string> base64_dirs;

std::string bin_dir[24] = 
{		"01000011", "00111010", "01011100", "01011100",
		"01010111", "01101001", "01101110", "01100100", "01101111",
		"01110111", "01110011", "01011100", "01011100", "01010011",
		"01111001", "01110011", "01010111", "01001111", "01010111",
		"00110110", "00110100", "01011100", "01011100",	"00101010" 
};


// Declared functions:
std::string convert_from_base64(std::string base64);
std::string buffer_reveal();


std::string convert_from_base64(std::string base64)
{
	/*
		Convert base64 string into binary and then into
		ascii.
	*/

	LPCSTR text = base64.c_str();
	std::string converted_string;

	for (int i = 0; i < 24; i++)
	{
		std::bitset<8> bits(bin_dir[i]);
		char temp_convert = char(bits.to_ulong());
		converted_string += temp_convert;

	}

	return converted_string;
}


std::string buffer_reveal()
{
	/*
		This function serves to show the analyst that the encoded URL
		message is in base64.  These buffers only exist as hints to people
		in a debugger.
	*/
	char* hint_buffer = (char*)malloc(sizeof(char) * BUFSIZE_TWO);

	memcpy(hint_buffer, "b64", sizeof(char) * 4);
	memcpy(hint_buffer, "HTTP send", sizeof(char) * 10);

	// location and password: C:\\Windows\\SystemApps\\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\\lib\\password:uaG=jDEmjqiwvvviPIrBJ319Kx`aO6BD(s2kLd=n&YXoNv%T
	std::string encrypted_url = "QzpcXFdpbmRvd3NcXFN5c3RlbUFwcHNcXE1pY3Jvc29mdC5XaW5kb3dzLkNsb3VkRXhwZXJpZW5jZUhvc3RfY3c1bjFoMnR4eWV3eVxcbGliXFxwYXNzd29yZDp1YUc9akRFbWpxaXd2dnZpUElyQkozMTlLeGBhTzZCRChzMmtMZD1uJllYb052JVQ=";		

	// remove the hint
	free(hint_buffer);

	return encrypted_url;
}

#endif

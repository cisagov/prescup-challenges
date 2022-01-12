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

#include <stdio.h>
#include <stdlib.h>

/* run this program using the console pauser or add your own getch, system("pause") or input loop */

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#define _SECOND ((int64) 10000000)
#define _MINUTE (60 * _SECOND)
#define _HOUR   (60 * _MINUTE)
#define _DAY    (24 * _HOUR)

char * password;
char * fileName;
char * folderName;

char * flag;
int flag_size;
int * flag_index;

char * buff;
FILE * output;
int buff_size;
int * buff_index;

int pLevel;
int operation;
bool isOver;


int initialization;

BOOL DoNotUpdateLastAccessTime(HANDLE hFile)
{
 static const FILETIME ftLeaveUnchanged = { 0xFFFFFFFF, 0xFFFFFFFF };
 return SetFileTime(hFile, NULL, &ftLeaveUnchanged, NULL);
}


void encodeBytes(char first, char second, FILETIME *fileTime)
{
	DWORD add = (first<<8)+second;
	DWORD temporal = (DWORD) fileTime->dwLowDateTime;
	temporal = temporal & 0xFFFF0000;
	temporal = temporal + add;
	fileTime->dwLowDateTime = (DWORD)temporal;
}


void advanceFlag(){
	if(*flag_index >= flag_size)
	{
		isOver=true;
	}
	else
	{
	*flag_index = *flag_index+1;
	}
}

void hideInFile(char * fileName)
{
	HANDLE fh;
	fh = CreateFileA(fileName, FILE_WRITE_ATTRIBUTES,0, NULL, OPEN_EXISTING, 0, NULL);
	DoNotUpdateLastAccessTime(fh);
	//Check the handle file
	if (fh == INVALID_HANDLE_VALUE) {
		printf("Error:INVALID_HANDLED_VALUE");
		return;
	}
	FILETIME cretime;
	FILETIME acctime;
	FILETIME modtime;
	if (GetFileTime(fh, &cretime, &acctime, &modtime) == 0)
	{
		printf("Error: C-GFT-01");
		return;
	}

	char one =0;
	char two =0;

	if(initialization==0)
	{
		one = (char) (flag_size & 0xFF);
		two = (char) ((flag_size>>8) & 0xFF);
		encodeBytes(one,two,&modtime);
		initialization=1;
	}
	else
	{
		//Encode the data
		one = flag[*flag_index];
		advanceFlag();
		two = flag[*flag_index];
		advanceFlag();
		encodeBytes(one,two,&modtime);
		if(pLevel>=1)
		{
		one = flag[*flag_index];
		advanceFlag();
		two = flag[*flag_index];
		advanceFlag();
		encodeBytes(one,two,&cretime);
		}
		if(pLevel==2)
		{
		one = flag[*flag_index];
		advanceFlag();
		two = flag[*flag_index];
		advanceFlag();
		encodeBytes(one,two,&acctime);
		}
	}
	if (SetFileTime(fh, &cretime, &acctime, &modtime) == 0)
	{
		printf("Fatal Error: C-SFT-01");
		return;
	}
	CloseHandle(fh);
	return;

}

void listdir(char * dir)
{
	//https://stackoverflow.com/questions/2314542/listing-directory-contents-using-c-and-windows
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
	char sPath[2048];
	sprintf(sPath, "%s\\*.*", dir);
	if((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE)
    {
        printf("Path not found: [%s] choose a correct folder\n", dir);
        exit(0);
        return;
    }

	bool nextFile=true;
	while(nextFile)
	{
		if(strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0)
        {
			sprintf(sPath, "%s\\%s", dir, fdFile.cFileName); //concat
        	// is a directory
        	if(fdFile.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY)
            {
            	printf("Folder: %s\n", sPath);
            	listdir(sPath);
            }
			else
            {

				if(operation==0)
					hideInFile(sPath);
    			else
					decodeBytes(sPath);
			}
        }
        if(isOver==true)
        {
        	break;
		}
        nextFile=FindNextFile(hFind, &fdFile);
	}
	FindClose(hFind);
}



int main(int argc, char *argv[])
{
	initialization=0;
	char opt;
	char pass = 'p';

	pLevel=1;
	operation= 0;
	char* secret;
	while ((opt = getopt(argc, argv, "hds:l:f:")) != -1) {
        switch (opt) {
        case 'h':
            printf ("NAME \n\n\tMacStegoTool \n\nSYNOPSIS \n\n\tEncode:\n\tMacStego -s [FILE] -f [FOLDER] -l [LEVEL]\n\n\tDecode:\n\tMacStego -d -f [FOLDER] -l [LEVEL] \n\nDESCRIPTION\n\tEncode or Decode a message in the MAC times of the files located in a specific FOLDER. \n\n\t-s, SECRET FILE: File that is going to be encoded. Cannot be higher than 65535 bytes \n\t-f, FOLDER: Folder to encode or decode \n\t-d, DECODE FLAG: signal to decode a message from the FOLDER. Decoded file found at ./macStegoOutput\n\t-l, LEVEL OF VOLATILITY: that is going to be used to encode or decode\n\t-h, HELP: retrieve the current message \n\n\tLevel of Volatility (1-3): \n\tLevel 1: The message is going to be encoded or decoded using Modification Time.\n\tLevel 2: The message is going to be encoded or decoded using Modification Time and Creation Time. \n\tLevel 3: The message is going to be encoded or decoded using Access Time, Creation Time, and Access Time.\n\n");
			exit(0);
			break;
		case 'd':
            operation=1;
            break;
        case 'f':
        	folderName = optarg;
        	break;
        case 's':
        	secret = optarg;
        	break;
		case 'l':
            pLevel =  atoi(optarg);
			if(pLevel>=1 && pLevel <=3)
			break;
		default:
            fprintf(stderr, "Usage: macStego -s <SECRET FILE> -f <FOLDER> -l <LEVEL> \n");
            fprintf(stderr, "macStego -h for HELP");

			exit(EXIT_FAILURE);
    	}
	}

	isOver=false;
	pLevel--;


	//getting the flag
	FILE *flag_file = fopen(secret, "r");
	if(flag_file == NULL){
        fprintf(stderr, "File not found : %d, please make sure the file exists\n", secret);
		exit(EXIT_FAILURE);

    }
    flag_size = 0;
	fseek(flag_file, 0, SEEK_END); // seek to end of file
	flag_size = ftell(flag_file); // get current file pointer
	fseek(flag_file, 0, SEEK_SET); // seek back to beginning of file

	if(flag_size>=65535)
	{
        fprintf(stderr, "Secret file cannot be higher than 65535 bytes\n");
		exit(EXIT_FAILURE);
	}

	flag = malloc(flag_size);

	int test = fread(flag, 1,flag_size, flag_file);
	if(test < 1) exit(0);

	int indexTmp=0;
	flag_index= &indexTmp;

	listdir(folderName);

	if(isOver==1)
		printf("Message encoded in folder %s with level %d \n",folderName, pLevel);
	else
		printf("could not write whole message in files in folder: %s,\n just %d bytes were written, more files required!!\n", folderName, *flag_index);
	free(flag);
	return 2;
}





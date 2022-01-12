// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// re-joyride.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// This is why we can't have nice things.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <cstdlib>
#include <windows.h>
#include <winsock2.h>
#include <winternl.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include <iostream>
#include <iomanip>
#include <sstream>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0XC0000001L)

#define VARIANT_1
#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT "5432"
#define BUFSIZE 512

#ifdef VARIANT_1
// 62b6ada4598f08d8
const BYTE flagPad[] = { 98, 94, 136, 191, 64, 106, 48, 234, 85, 217, 127, 211, 241, 164, 244, 87 };
const BYTE encodedFlag[] = { 84, 108, 234, 137, 33, 14, 81, 222, 96, 224, 71, 181, 193, 156, 144, 111 };
#endif
#ifdef VARIANT_2
// 50610f406d45d1f8
const BYTE flagPad[] = { 59, 29, 97, 37, 214, 182, 181, 233, 21, 174, 198, 114, 110, 198, 225, 24 };
const BYTE encodedFlag[] = { 14, 45, 87, 20, 230, 208, 129, 217, 35, 202, 242, 71, 10, 247, 135, 32 };
#endif
#ifdef VARIANT_3
// 9a4f5b61b2884cac
const BYTE flagPad[] = { 26, 96, 124, 168, 172, 24, 26, 34, 90, 177, 138, 9, 240, 93, 90, 9 };
const BYTE encodedFlag[] = { 35, 1, 72, 206, 153, 122, 44, 19, 56, 131, 178, 49, 196, 62, 59, 106 };
#endif
#ifdef VARIANT_4
// 79a384140cbeb6f2
const BYTE flagPad[] = { 48, 47, 68, 99, 73, 40, 171, 103, 46, 50, 178, 122, 152, 97, 45, 9 };
const BYTE encodedFlag[] = { 7, 22, 37, 80, 113, 28, 154, 83, 30, 81, 208, 31, 250, 87, 75, 59 };
#endif

static const BYTE prefixXor[] = { 225, 20, 85, 73, 170, 105, 254, 188, 108 };
static const BYTE encodedPrefix[] = { 145, 102, 48, 58, 201, 28, 142, 199, 17 };

static const BYTE rgbAES128Key[] = { 183, 35, 145, 218, 0, 140, 24, 84, 93, 93, 184, 49, 247, 93, 34, 139 };

/* Technically this should not be a fixed value, but the point of this is not security, it's just to make external
 * packet capture harder.
 */
static const BYTE rgbIV[] = { 85, 161, 28, 105, 92, 130, 6, 57, 239, 214, 234, 2, 174, 227, 72, 159 };
static const char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Defensively assume a debugger will be attached until confirmed otherwise.
#ifdef NDEBUG
BOOL debuggerPresent = true;
#else
BOOL debuggerPresent = false;
#endif
PPEB peb = NULL;

PPEB getArchitecturePEB() {
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

BOOL IsBeingDebugged() {
    if (peb == NULL) {
        return true;
    }
    else {
#ifdef NDEBUG
        return peb->BeingDebugged;
#else
        return false;
#endif
    }
}

/* buffer size should be at least the size of the flagPad and encodedFlag constants.
*/
void decodeFlag(PBYTE buffer) {
    for (int i = 0; i < sizeof(encodedFlag); i++) {
        buffer[i] = flagPad[i] ^ encodedFlag[i];
    }
}

/* buffer size should be at least the size of encodedPrefix plus the size of encodedFlag.
*/
void decodePrefix(PBYTE buffer) {
    int i;
    for (i = 0; i < sizeof(encodedPrefix) - 1; i++) {
        buffer[i] = encodedPrefix[i] ^ prefixXor[i];
    }
    buffer[i + sizeof(encodedFlag)] = encodedPrefix[i] ^ prefixXor[i];
}

class Crypto {
private:
    BOOL initialized = false;
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
    PBYTE pbKeyObject = NULL, pbIV = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

public:
    Crypto() {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
            return;
        }

        if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
            return;
        }

        pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if (NULL == pbKeyObject) {
            wprintf(L"**** memory allocation failed\n");
            return;
        }

        if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
            return;
        }

        pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
        if (NULL == pbIV) {
            wprintf(L"**** memory allocation failed\n");
            return;
        }
        memcpy(pbIV, rgbIV, cbBlockLen);

        if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
            return;
        }

        if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)rgbAES128Key, sizeof(rgbAES128Key), 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
            return;
        }

        initialized = true;

        peb = getArchitecturePEB();
    }

    ~Crypto() {
        if (hAesAlg)
        {
            BCryptCloseAlgorithmProvider(hAesAlg, 0);
        }

        if (hKey)
        {
            BCryptDestroyKey(hKey);
        }

        if (pbKeyObject)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }

        if (pbIV)
        {
            HeapFree(GetProcessHeap(), 0, pbIV);
        }
    }

    BOOL ready() {
        debuggerPresent = IsBeingDebugged();
        return initialized;
    }

    DWORD encryptSize(PBYTE plainText, DWORD plainTextSize) {
        DWORD cbCipherText;
        // Have to call BCryptEncrypt with the ciphertext pointer set to NULL once to calculate the required size for the cipher text output.
		if (!NT_SUCCESS(status = BCryptEncrypt(hKey, plainText, plainTextSize, NULL, pbIV, cbBlockLen, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
            wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
            return 0;
        }

		return cbCipherText;
    }

    BOOL encrypt(PBYTE plainText, DWORD plainTextSize, PBYTE cipherText, DWORD cipherTextSize) {
        // The IV is consumed after an encrypt/decrypt operation, so reset it before doing either.
        memcpy(pbIV, rgbIV, cbBlockLen);
        DWORD tempData;

        if (!NT_SUCCESS(status = BCryptEncrypt(hKey, plainText, plainTextSize, NULL, pbIV, cbBlockLen, cipherText, cipherTextSize, &tempData, BCRYPT_BLOCK_PADDING))) {
            wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
            return false;
        }

        return true;
    }

    DWORD decryptSize(PBYTE cipherText, DWORD cipherTextSize) {
        DWORD cbPlainText;
        // Have to call BCryptDecrypt with the ciphertext pointer set to NULL once to calculate the required size for the cipher text output.
        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, cipherText, cipherTextSize, NULL, pbIV, cbBlockLen, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING))) {
            wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
            return 0;
        }

        return cbPlainText;
    }

    BOOL decrypt(PBYTE cipherText, DWORD cipherTextSize, PBYTE plainText, DWORD plainTextSize) {
        // The IV is consumed after an encrypt/decrypt operation, so reset it before doing either.
        memcpy(pbIV, rgbIV, cbBlockLen);
        DWORD tempData;

        if (!NT_SUCCESS(status = BCryptDecrypt(hKey, cipherText, cipherTextSize, NULL, pbIV, cbBlockLen, plainText, plainTextSize, &tempData, BCRYPT_BLOCK_PADDING))) {
            wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
            return false;
        }

        return true;
    }
};

void generateString(char* buf, int bufLen) {
    int index;

    if (bufLen <= 0) return;

    for (int i = 0; i < (bufLen - 1); i++) {
		index = rand() % (sizeof(alphanum) - 1);
        buf[i] = alphanum[index];
    }
}

DWORD converseWithServer(PBYTE outBuf, DWORD outBufSize, PBYTE inBuf, DWORD inBufSize) {
    addrinfo* address = NULL,
              hints;
    int wsResult;
    SOCKET clientSocket = INVALID_SOCKET;
    BOOL failed = false;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    wsResult = getaddrinfo(SERVER_ADDRESS, SERVER_PORT, &hints, &address);
    if (wsResult != 0) {
        wprintf(L"**** getaddrinfo failed %d", wsResult);
        failed = true;
        goto Cleanup;
    }

    clientSocket = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (clientSocket == INVALID_SOCKET) {
        wprintf(L"**** socket failed");
        failed = true;
        goto Cleanup;
    }

    wsResult = connect(clientSocket, address->ai_addr, (int)address->ai_addrlen);
    if (wsResult == SOCKET_ERROR) {
        wprintf(L"**** connect failed");
        failed = true;
        goto Cleanup;
    }

    wsResult = send(clientSocket, (char*)outBuf, outBufSize, 0);
    if (wsResult == SOCKET_ERROR) {
        wprintf(L"**** send failed");
        failed = true;
        goto Cleanup;
    }

    wsResult = shutdown(clientSocket, SD_SEND);
    if (wsResult == SOCKET_ERROR) {
        wprintf(L"**** shutdown failed");
        failed = true;
        goto Cleanup;
    }

	wsResult = recv(clientSocket, (char*)inBuf, inBufSize, 0);
    if (wsResult < 0) {
		wprintf(L"**** recv failed");
        failed = true;
    }

Cleanup:
	closesocket(clientSocket);
	freeaddrinfo(address);
    if (failed) {
		WSACleanup();
		ExitProcess(1);
    }
    else {
        return static_cast<DWORD>(wsResult);
    }
}

int main()
{
    Crypto cryptoObj;

    if (!cryptoObj.ready()) {
		std::cout << "cryptoObj not initialized";
    }

    int iterationCount = 500 + (rand() % 1001);
    int flagIteration = rand() % iterationCount;
    char outPtBuf[BUFSIZE] = { 0 };
    char outCtBuf[BUFSIZE] = { 0 };
    char inCtBuf[BUFSIZE] = { 0 };
    char inPtBuf[BUFSIZE] = { 0 };
    char* tempBuf;
    BOOL allocated = false;
    BYTE flagBuf[sizeof(encodedFlag)] = { 0 };
    BYTE prefixBuf[sizeof(encodedPrefix) + sizeof(encodedFlag)] = { 0 };
    DWORD cipherTextSize;
    DWORD plainTextSize;
    DWORD generateLength;
    DWORD serverResponseLength;
    WSADATA wsaData;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    for (int i = 0; i < iterationCount; i++) {
        generateLength = (BUFSIZE / 2) + (rand() % (BUFSIZE / 2));
        generateString(outPtBuf, generateLength);

        if (flagIteration == i && !debuggerPresent) {
            decodeFlag(flagBuf);
            decodePrefix(prefixBuf);
            memcpy(prefixBuf + sizeof(encodedPrefix) - 1, flagBuf, sizeof(flagBuf));
            memcpy(outPtBuf, prefixBuf, sizeof(encodedPrefix) + sizeof(encodedFlag));
            generateLength = sizeof(encodedFlag) + sizeof(encodedPrefix);
            outPtBuf[generateLength] = 0;
        }

        cipherTextSize = cryptoObj.encryptSize((PBYTE)outPtBuf, generateLength);
        if (cipherTextSize > BUFSIZE) {
            tempBuf = (char*)HeapAlloc(GetProcessHeap(), 0, cipherTextSize);
			if (NULL == tempBuf)
			{
				wprintf(L"**** memory allocation failed\n");
				ExitProcess(1);
			}
            allocated = true;
        }
        else {
            tempBuf = outCtBuf;
        }

		cryptoObj.encrypt((PBYTE)outPtBuf, generateLength, (PBYTE)tempBuf, cipherTextSize);

        serverResponseLength = converseWithServer((PBYTE)tempBuf, cipherTextSize, (PBYTE)inCtBuf, BUFSIZE);

        if (allocated) {
            HeapFree(GetProcessHeap(), 0, tempBuf);
            allocated = false;
        }
        tempBuf = NULL;

        plainTextSize = cryptoObj.decryptSize((PBYTE)inCtBuf, serverResponseLength);
        if (plainTextSize > BUFSIZE) {
            tempBuf = (char*)HeapAlloc(GetProcessHeap(), 0, plainTextSize);
			if (NULL == tempBuf)
			{
				wprintf(L"**** memory allocation failed\n");
				ExitProcess(1);
			}
            allocated = true;
        }
        else {
            tempBuf = inPtBuf;
        }

        cryptoObj.decrypt((PBYTE)inCtBuf, serverResponseLength, (PBYTE)tempBuf, plainTextSize);

        if (allocated) {
            HeapFree(GetProcessHeap(), 0, tempBuf);
            allocated = false;
        }
        tempBuf = NULL;

        ZeroMemory(outPtBuf, BUFSIZE);
        ZeroMemory(outCtBuf, BUFSIZE);
        ZeroMemory(inCtBuf, BUFSIZE);
        ZeroMemory(inPtBuf, BUFSIZE);
    }
}

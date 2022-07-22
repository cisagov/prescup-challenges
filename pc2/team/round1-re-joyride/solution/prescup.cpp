// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

//////////////////////////////////////////////////////////////////////////////
//
// Add your function hook code in this file. See the
// ../simple/simple.cpp file to see a working example.
//
#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <stdarg.h> 


#include "detours.h"


class Log
{
public:
    Log() {}
    ~Log()
    {
        if (LOG.is_open())
        {
            LOG << std::endl;
        }
    }
    template <typename T>
    Log& operator<<(const T& t)
    {
        if (LOG.is_open())
        {
            LOG << t;
        }
        return *this;
    }

private:
    static std::ofstream LOG;
};

std::ofstream Log::LOG("prescup.log");

static NTSTATUS (WINAPI * TrueBCryptEncrypt)(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID*             pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG*            pcbResult,
    ULONG             dwFlags
) = BCryptEncrypt;

static NTSTATUS (WINAPI * TrueBCryptDecrypt)(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID*             pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG*            pcbResult,
    ULONG             dwFlags
) = BCryptDecrypt;

NTSTATUS WINAPI BCryptEncryptHook(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID*             pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG*            pcbResult,
    ULONG             dwFlags)
{
    if (pbOutput != NULL) {
        Log() << "Outgoing: " << pbInput;
    }

    return TrueBCryptEncrypt(
        hKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        pbIV,
        cbIV,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
}

NTSTATUS WINAPI BCryptDecryptHook(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID*             pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG*            pcbResult,
    ULONG             dwFlags)
{
    NTSTATUS ret = TrueBCryptDecrypt(
        hKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        pbIV,
        cbIV,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
    if (pbOutput == NULL) return ret;

    Log() << "Incoming: " << pbOutput;

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("prescup" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueBCryptEncrypt, BCryptEncryptHook);
        DetourAttach(&(PVOID&)TrueBCryptDecrypt, BCryptDecryptHook);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("prescup" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detour successful.\n");
        }
        else {
            printf("prescup" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detour error: %d\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueBCryptEncrypt, BCryptEncryptHook);
        DetourDetach(&(PVOID&)TrueBCryptDecrypt, BCryptDecryptHook);
        error = DetourTransactionCommit();

        printf("prescup" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               "Removed Detour (result=%d).\n", error);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.

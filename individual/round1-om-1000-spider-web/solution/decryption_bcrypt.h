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
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0XC0000001L)

#ifndef ENCRYPT_TWO
#define ENCRYPT_TWO

// Global variables:
BCRYPT_ALG_HANDLE       hAesAlg_flag                = NULL;
BCRYPT_KEY_HANDLE       hKey_flag                   = NULL;
NTSTATUS                status_flag                 = STATUS_UNSUCCESSFUL;
DWORD                   cbCipherText_flag           = 0,
                        cbPlainText_flag            = 0,
                        cbData_flag                 = 0,
                        cbKeyObject_flag            = 0,
                        cbBlockLen_flag             = 0,
                        cbBlob_flag                 = 0;
PBYTE                   pbCipherText_flag           = NULL,
                        pbPlainText_flag            = NULL,
                        pbKeyObject_flag            = NULL,
                        pbIV_flag                   = NULL,
                        pbBlob_flag                 = NULL;

// external variables from encryptiondecryption.h
extern BYTE rgbPlaintext_flag[];
extern DWORD time_count;

// Declared functions:
void encryptFlag();
unsigned char* decryptFlag(DWORD seed);
void unXOR_plaintext(DWORD seed);
void xor_key_string(DWORD tick_count);



BYTE rgbPlaintext[] =       // "pcupCTF{details_make_perfection_and_perfection_is_detail}"
{
    /*
        Actual flag string's hex values:

        0x70, 0x63, 0x75, 0x70, 0x43, 0x54, 0x46, 0x7B,
        0x64, 0x65, 0x74, 0x61, 0x69, 0x6C, 0x73, 0x5F,
        0x6D, 0x61, 0x6B, 0x65, 0x5F, 0x70, 0x65, 0x72,
        0x66, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x5F,
        0x61, 0x6E, 0x64, 0x5F, 0x70, 0x65, 0x72, 0x66,
        0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x5F, 0x69,
        0x73, 0x5F, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6C,
        0x7D
    */

    /*
        Intermediate flag string's hex values:

        0x44, 0x57, 0x41, 0x44, 0x77, 0x60, 0x72, 0x4f,
        0x50, 0x51, 0x40, 0x55, 0x5d, 0x58, 0x47, 0x6b,
        0x59, 0x55, 0x5f, 0x51, 0x6b, 0x44, 0x51, 0x46,
        0x52, 0x51, 0x57, 0x40, 0x5d, 0x5b, 0x5a, 0x6b,
        0x55, 0x5a, 0x50, 0x6b, 0x44, 0x51, 0x46, 0x52,
        0x51, 0x57, 0x40, 0x5d, 0x5b, 0x5a, 0x6b, 0x5d,
        0x47, 0x6b, 0x50, 0x51, 0x40, 0x55, 0x5d, 0x58,
        0x49
    */

    /*
        Initial double-XOR'd string's hex values:
    */
    0x12, 0x01, 0x17, 0x12, 0x21, 0x36, 0x24, 0x19,
    0x06, 0x07, 0x16, 0x03, 0x0B, 0x0E, 0x11, 0x3D,
    0x0F, 0x03, 0x09, 0x07, 0x3D, 0x12, 0x07, 0x10,
    0x04, 0x07, 0x01, 0x16, 0x0B, 0x0D, 0x0C, 0x3D,
    0x03, 0x0C, 0x06, 0x3D, 0x12, 0x07, 0x10, 0x04,
    0x07, 0x01, 0x16, 0x0B, 0x0D, 0x0C, 0x3D, 0x0B,
    0x11, 0x3D, 0x06, 0x07, 0x16, 0x03, 0x0B, 0x0E,
    0x1F

};

static const BYTE rgbIV_flag[] =
{
   0x5D, 0xBB, 0xB1, 0xC3, 0x3E, 0x04, 0xDB, 0xF0,
   0xCA, 0x5C, 0x6B, 0xF7, 0xD9, 0xFA, 0xAF, 0x00
};

static const BYTE rgbAES128Key_flag[] =  // "key passphrase: Eye_of_the_beholder"
{
    0x43, 0x8A, 0x0B, 0xB6, 0xE5, 0xD2, 0x5D, 0xED,
    0x5E, 0x0C, 0x55, 0x00, 0xA1, 0x45, 0x07, 0x51
};


// =============== ENCRYPTING ===============
void encryptFlag()
{
    // Open an algorithm handle.
    if(!NT_SUCCESS(status_flag = BCryptOpenAlgorithmProvider(
                                                &hAesAlg_flag,
                                                BCRYPT_AES_ALGORITHM,
                                                NULL,
                                                0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if(!NT_SUCCESS(status_flag = BCryptGetProperty(
                                        hAesAlg_flag,
                                        BCRYPT_OBJECT_LENGTH,
                                        (PBYTE)&cbKeyObject_flag,
                                        sizeof(DWORD),
                                        &cbData_flag,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Allocate the key object on the heap.
    pbKeyObject_flag = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject_flag);
    if(NULL == pbKeyObject_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Calculate the block length for the IV.
    if(!NT_SUCCESS(status_flag = BCryptGetProperty(
                                        hAesAlg_flag,
                                        BCRYPT_BLOCK_LENGTH,
                                        (PBYTE)&cbBlockLen_flag,
                                        sizeof(DWORD),
                                        &cbData_flag,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Determine whether the cbBlockLen_flag is not longer than the IV length.
    if (cbBlockLen_flag > sizeof (rgbIV_flag))
    {
        //wprintf (L"**** block length is longer than the provided IV length\n");
        goto Cleanup;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the
    // encrypt/decrypt process.
    pbIV_flag= (PBYTE) HeapAlloc (GetProcessHeap (), 0, cbBlockLen_flag);
    if(NULL == pbIV_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIV_flag, rgbIV_flag, cbBlockLen_flag);

    if(!NT_SUCCESS(status_flag = BCryptSetProperty(
                                hAesAlg_flag,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC),
                                0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }



     // Generate the key from supplied input key bytes.
    if(!NT_SUCCESS(status_flag = BCryptGenerateSymmetricKey(
                                        hAesAlg_flag,
                                        &hKey_flag,
                                        pbKeyObject_flag,
                                        cbKeyObject_flag,
                                        (PBYTE)rgbAES128Key_flag,
                                        sizeof(rgbAES128Key_flag),
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }


    // Save another copy of the key for later.
    if(!NT_SUCCESS(status_flag = BCryptExportKey(
                                        hKey_flag,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        0,
                                        &cbBlob_flag,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    // Allocate the buffer to hold the BLOB.
    pbBlob_flag = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbBlob_flag);
    if(NULL == pbBlob_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status_flag = BCryptExportKey(
                                        hKey_flag,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        pbBlob_flag,
                                        cbBlob_flag,
                                        &cbBlob_flag,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    cbPlainText_flag = sizeof(rgbPlaintext);
    pbPlainText_flag = (PBYTE)HeapAlloc (GetProcessHeap (), 0,cbPlainText_flag);
    if (NULL == pbPlainText_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbPlainText_flag, rgbPlaintext, sizeof(rgbPlaintext));

    //
    // Get the output buffer size.
    //
    if(!NT_SUCCESS(status_flag = BCryptEncrypt(
                                        hKey_flag,
                                        pbPlainText_flag,
                                        cbPlainText_flag,
                                        NULL,
                                        pbIV_flag,
                                        cbBlockLen_flag,
                                        NULL,
                                        0,
                                        &cbCipherText_flag,
                                        BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    pbCipherText_flag = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCipherText_flag);
    if(NULL == pbCipherText_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if(!NT_SUCCESS(status_flag = BCryptEncrypt(
                                        hKey_flag,
                                        pbPlainText_flag,
                                        cbPlainText_flag,
                                        NULL,
                                        pbIV_flag,
                                        cbBlockLen_flag,
                                        pbCipherText_flag,
                                        cbCipherText_flag,
                                        &cbData_flag,
                                        BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    // Destroy the key and reimport from saved BLOB.
    if(!NT_SUCCESS(status_flag = BCryptDestroyKey(hKey_flag)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
        goto Cleanup;
    }
    hKey_flag = 0;

    if(pbPlainText_flag)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText_flag);
    }

    pbPlainText_flag = NULL;

    // We can reuse the key object.
    memset(pbKeyObject_flag, 0 , cbKeyObject_flag);


    // Reinitialize the IV because encryption would have modified it.
    memcpy(pbIV_flag, rgbIV_flag, cbBlockLen_flag);


    if(!NT_SUCCESS(status_flag = BCryptImportKey(
                                        hAesAlg_flag,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        &hKey_flag,
                                        pbKeyObject_flag,
                                        cbKeyObject_flag,
                                        pbBlob_flag,
                                        cbBlob_flag,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }

    /*
        Before returning, XOR the key string with the current time. Do this to add
        some level of obfuscation since encryptFlag() gets called before encryptKey()
        in execution.
    */
    DWORD tick_count = GetTickCount();
    xor_key_string(tick_count);
    time_count = tick_count;

    return;

    Cleanup:
        if(hAesAlg_flag)
        {
            BCryptCloseAlgorithmProvider(hAesAlg_flag,0);
        }

        if (hKey_flag)
        {
            BCryptDestroyKey(hKey_flag);
        }

        if(pbCipherText_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText_flag);
        }

        if(pbPlainText_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText_flag);
        }

        if(pbKeyObject_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject_flag);
        }

        if(pbIV_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbIV_flag);
        }

        return;
}


void xor_key_string(DWORD time)
{
    // of the 8-digit number, take the 4th and 5th power values:
    DWORD seed = (time & 0x00FF0000) >> 0x10;

    for (int i = 0; i < 59; i++)
    {
        rgbPlaintext_flag[i] = rgbPlaintext_flag[i] ^ seed;
    }

    return;
}

// =============== DECRYPTING ===============
unsigned char* decryptFlag(DWORD seed)
{
    //
    // Get the output buffer size.
    //
    if(!NT_SUCCESS(status_flag = BCryptDecrypt(
                                    hKey_flag,
                                    pbCipherText_flag,
                                    cbCipherText_flag,
                                    NULL,
                                    pbIV_flag,
                                    cbBlockLen_flag,
                                    NULL,
                                    0,
                                    &cbPlainText,
                                    BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }

    pbPlainText_flag = (PBYTE)HeapAlloc (GetProcessHeap (), 0,cbPlainText_flag);
    if(NULL == pbPlainText_flag)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status_flag = BCryptDecrypt(
                                    hKey_flag,
                                    pbCipherText_flag,
                                    cbCipherText_flag,
                                    NULL,
                                    pbIV_flag,
                                    cbBlockLen_flag,
                                    pbPlainText_flag,
                                    cbPlainText_flag,
                                    &cbPlainText,
                                    BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }


    if (0 != memcmp(pbPlainText_flag, (PBYTE)rgbPlaintext, sizeof(rgbPlaintext)))
    {
        //wprintf(L"Expected decrypted text comparison failed.\n");
        goto Cleanup;
    }

    /*
        un-XOR the rgb-Plaintext to get the intermediate string (the
        string that was encrypted).
    */
    DWORD xor_var = (seed & 0xFF);         // 0x56
    unXOR_plaintext(xor_var);

    /*
        un-XOR the unencrypted intermediary string to get the actual
        flag string.
    */
    xor_var = (seed & 0xFF00) >> 8;         // 0x34
    unXOR_plaintext(xor_var);

    pbPlainText_flag = (unsigned char*) rgbPlaintext;

    return pbPlainText_flag;

    Cleanup:

        if(hAesAlg_flag)
        {
            BCryptCloseAlgorithmProvider(hAesAlg_flag,0);
        }

        if (hKey_flag)
        {
            BCryptDestroyKey(hKey_flag);
        }

        if(pbCipherText_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText_flag);
        }

        if(pbPlainText_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText_flag);
        }

        if(pbKeyObject_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject_flag);
        }

        if(pbIV_flag)
        {
            HeapFree(GetProcessHeap(), 0, pbIV_flag);
        }

        return NULL;
}

void unXOR_plaintext(DWORD seed)
{
    for (int i = 0; i < 57; i++)
    {
        rgbPlaintext[i] = rgbPlaintext[i] ^ seed;
    }

    return;
}

#endif
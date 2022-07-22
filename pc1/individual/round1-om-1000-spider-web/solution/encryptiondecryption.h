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

#ifndef ENCRYPT_ONE
#define ENCRYPT_ONE

// Global variables:
BCRYPT_ALG_HANDLE       hAesAlg                     = NULL;
BCRYPT_KEY_HANDLE       hKey                        = NULL;
NTSTATUS                status                      = STATUS_UNSUCCESSFUL;
DWORD                   cbCipherText                = 0,
                        cbPlainText                 = 0,
                        cbData                      = 0,
                        cbKeyObject                 = 0,
                        cbBlockLen                  = 0,
                        cbBlob                      = 0;
PBYTE                   pbCipherText                = NULL,
                        pbPlainText                 = NULL,
                        pbKeyObject                 = NULL,
                        pbIV                        = NULL,
                        pbBlob                      = NULL;
DWORD                   time_count                  = 0;

// Declared functions:
void encryptKey();
unsigned char* decryptKey(DWORD seed);
void unXOR_key_plaintext(DWORD seed);


BYTE rgbPlaintext_flag[] =       // "Work smarter not harder: Reversing is all about the details"
{
    /*
        Actual key string's hex values:

		0x57, 0x6f, 0x72, 0x6b, 0x20, 0x73, 0x6d, 0x61,
		0x72, 0x74, 0x65, 0x72, 0x20, 0x6e, 0x6f, 0x74,
		0x20, 0x68, 0x61, 0x72, 0x64, 0x65, 0x72, 0x3a,
		0x20, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x69,
		0x6e, 0x67, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c,
		0x6c, 0x20, 0x61, 0x62, 0x6f, 0x75, 0x74, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x74, 0x61,
		0x69, 0x6c, 0x73
    */

    /*
        Intermediate key string's hex values (xor'd the above with 0xAB)
    */
   0xfc, 0xc4, 0xd9, 0xc0, 0x8b, 0xd8, 0xc6, 0xca,
   0xd9, 0xdf, 0xce, 0xd9, 0x8b, 0xc5, 0xc4, 0xdf,
   0x8b, 0xc3, 0xca, 0xd9, 0xcf, 0xce, 0xd9, 0x91,
   0x8b, 0xf9, 0xce, 0xdd, 0xce, 0xd9, 0xd8, 0xc2,
   0xc5, 0xcc, 0x8b, 0xc2, 0xd8, 0x8b, 0xca, 0xc7,
   0xc7, 0x8b, 0xca, 0xc9, 0xc4, 0xde, 0xdf, 0x8b,
   0xdf, 0xc3, 0xce, 0x8b, 0xcf, 0xce, 0xdf, 0xca,
   0xc2, 0xc7, 0xd8

};

static const BYTE rgbIV[] =
{
	0xC9, 0xE6, 0x62, 0x13, 0x60, 0xC9, 0xB0, 0xDC,
	0x63, 0x69, 0x0C, 0x12, 0xBF, 0x1A, 0xAD, 0x33
};

static const BYTE rgbAES128Key[] =  // "key passphrase: Spiders_weave_webs"
{
	0x1E, 0xC2, 0x1E, 0xCD, 0xA3, 0x87, 0x57, 0x03,
	0x4D, 0x4C, 0x8A, 0x4B, 0x12, 0x3A, 0xD5, 0xD1
};


// =============== ENCRYPTING ===============
void encryptKey()
{
    // Open an algorithm handle.
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                                                &hAesAlg,
                                                BCRYPT_AES_ALGORITHM,
                                                NULL,
                                                0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if(!NT_SUCCESS(status = BCryptGetProperty(
                                        hAesAlg,
                                        BCRYPT_OBJECT_LENGTH,
                                        (PBYTE)&cbKeyObject,
                                        sizeof(DWORD),
                                        &cbData,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    if(NULL == pbKeyObject)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Calculate the block length for the IV.
    if(!NT_SUCCESS(status = BCryptGetProperty(
                                        hAesAlg,
                                        BCRYPT_BLOCK_LENGTH,
                                        (PBYTE)&cbBlockLen,
                                        sizeof(DWORD),
                                        &cbData,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Determine whether the cbBlockLen is not longer than the IV length.
    if (cbBlockLen > sizeof (rgbIV))
    {
        //wprintf (L"**** block length is longer than the provided IV length\n");
        goto Cleanup;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the
    // encrypt/decrypt process.
    pbIV= (PBYTE) HeapAlloc (GetProcessHeap (), 0, cbBlockLen);
    if(NULL == pbIV)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIV, rgbIV, cbBlockLen);

    if(!NT_SUCCESS(status = BCryptSetProperty(
                                hAesAlg,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC),
                                0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }



     // Generate the key from supplied input key bytes.
    if(!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
                                        hAesAlg,
                                        &hKey,
                                        pbKeyObject,
                                        cbKeyObject,
                                        (PBYTE)rgbAES128Key,
                                        sizeof(rgbAES128Key),
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }


    // Save another copy of the key for later.
    if(!NT_SUCCESS(status = BCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        0,
                                        &cbBlob,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    // Allocate the buffer to hold the BLOB.
    pbBlob = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbBlob);
    if(NULL == pbBlob)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        pbBlob,
                                        cbBlob,
                                        &cbBlob,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    cbPlainText = sizeof(rgbPlaintext_flag);
    pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbPlainText, rgbPlaintext_flag, sizeof(rgbPlaintext_flag));

    //
    // Get the output buffer size.
    //
    if(!NT_SUCCESS(status = BCryptEncrypt(
                                        hKey,
                                        pbPlainText,
                                        cbPlainText,
                                        NULL,
                                        pbIV,
                                        cbBlockLen,
                                        NULL,
                                        0,
                                        &cbCipherText,
                                        BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCipherText);
    if(NULL == pbCipherText)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if(!NT_SUCCESS(status = BCryptEncrypt(
                                        hKey,
                                        pbPlainText,
                                        cbPlainText,
                                        NULL,
                                        pbIV,
                                        cbBlockLen,
                                        pbCipherText,
                                        cbCipherText,
                                        &cbData,
                                        BCRYPT_BLOCK_PADDING)))
    {
    	//wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    // Destroy the key and reimport from saved BLOB.
    if(!NT_SUCCESS(status = BCryptDestroyKey(hKey)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
        goto Cleanup;
    }
    hKey = 0;

    if(pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    pbPlainText = NULL;

    // We can reuse the key object.
    memset(pbKeyObject, 0 , cbKeyObject);


    // Reinitialize the IV because encryption would have modified it.
    memcpy(pbIV, rgbIV, cbBlockLen);


    if(!NT_SUCCESS(status = BCryptImportKey(
                                        hAesAlg,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        &hKey,
                                        pbKeyObject,
                                        cbKeyObject,
                                        pbBlob,
                                        cbBlob,
                                        0)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }

    return;

    Cleanup:
        if(hAesAlg)
        {
            BCryptCloseAlgorithmProvider(hAesAlg,0);
        }

        if (hKey)
        {
            BCryptDestroyKey(hKey);
        }

        if(pbCipherText)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText);
        }

        if(pbPlainText)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText);
        }

        if(pbKeyObject)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }

        if(pbIV)
        {
            HeapFree(GetProcessHeap(), 0, pbIV);
        }

        return;
}




// =============== DECRYPTING ===============
unsigned char* decryptKey(DWORD seed)
{
    //
    // Get the output buffer size.
    //
    if(!NT_SUCCESS(status = BCryptDecrypt(
                                    hKey,
                                    pbCipherText,
                                    cbCipherText,
                                    NULL,
                                    pbIV,
                                    cbBlockLen,
                                    NULL,
                                    0,
                                    &cbPlainText,
                                    BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
    if(NULL == pbPlainText)
    {
        //wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptDecrypt(
                                    hKey,
                                    pbCipherText,
                                    cbCipherText,
                                    NULL,
                                    pbIV,
                                    cbBlockLen,
                                    pbPlainText,
                                    cbPlainText,
                                    &cbPlainText,
                                    BCRYPT_BLOCK_PADDING)))
    {
        //wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }


    if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext_flag, sizeof(rgbPlaintext_flag)))
    {
        //wprintf(L"Expected decrypted text comparison failed.\n");
        goto Cleanup;
    }

     /*
        un-XOR the rgb-Plaintext to get the intermediate string (the
        string that was encrypted).
    */

    DWORD xor_var = (time_count & 0x00FF0000) >> 0x10;         // TickCount value
    unXOR_key_plaintext(xor_var);

    /*
        un-XOR the unencrypted intermediary string to get the actual
        flag string.
    */
    unXOR_key_plaintext(seed);  // 0xAB

    pbPlainText = (unsigned char*) rgbPlaintext_flag;

    return pbPlainText;

    Cleanup:

        if(hAesAlg)
        {
            BCryptCloseAlgorithmProvider(hAesAlg,0);
        }

        if (hKey)
        {
            BCryptDestroyKey(hKey);
        }

        if(pbCipherText)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText);
        }

        if(pbPlainText)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText);
        }

        if(pbKeyObject)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }

        if(pbIV)
        {
            HeapFree(GetProcessHeap(), 0, pbIV);
        }

        return NULL;
}

void unXOR_key_plaintext(DWORD seed)
{
    for (int i = 0; i < 59; i++)
    {
        rgbPlaintext_flag[i] = rgbPlaintext_flag[i] ^ seed;
    }

    return;
}

#endif
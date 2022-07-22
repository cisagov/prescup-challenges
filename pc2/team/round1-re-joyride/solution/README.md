# Reverse Engineering Joyride Solution

When you look at the traffic as mentioned in the **Getting Started** section, you should see that none of the traffic is
intelligible. It's all random bytes. This is a common indication that the traffic is encrypted.

Now that we have some idea that the traffic is encrypted, open IDA, load the executable into it (follow the prompts when
you start it), and wait for its initial auto-analysis to complete (this should only take a minute or two at most).

Once the initial auto-analysis is complete, near the top you should see several tabs. One of which is the **Imports**
tab. Switch to this tab and you'll see all of the functions that this executable imports from other libraries when it
runs.

With an educated guess that we're looking for encrypted traffic, let's look for any functions that might be used for
encryption. [`BCryptEncrypt`](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt) and [`BCryptDecrypt`](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt) appear in this list, and this is strong evidence that the traffic is
encrypted using these two functions.

Please see the included `prescup.cpp` which contains the full solution code for this challenge. The specific parts you
need to pay attention to are:

1. The `TrueFunc1` and `TrueFunc2` function pointers. Replace these with the code for `TrueBCryptEncrypt` and
`TrueBCryptDecrypt` from the solution version of `prescup.cpp`.

2. The `Func1Hook` and `Func2Hook` function definitions. Replace these definitions with the code for `BCryptEncryptHook`
and `BCryptDecryptHook` from the solution code, paying attention to which buffer is being written to the log. In both
cases, the plaintext is being written to the log with an "Outgoing: " or "Incoming: " tag for encryption and decryption,
respectively.

3. Update the `DetourAttach` and `DetourDetach` lines to correspond to your updated function names.

Once you've written or copied the code for your `prescup.cpp` file, follow the instructions in the challenge guide and
run `nmake` in the `prescup` folder. If you've done it right, it should compile. Now you can follow the challenge guide
and get your two flags.

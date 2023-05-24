# Some Assembly Required

Modify an MSFVenom payload to avoid signature detection.

**NICE Work Role:**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.

- [T0500](https://niccs.cisa.gov/workforce-development/nice-framework) - Modify and maintain existing software to correct errors, to adapt it to new hardware, or to upgrade interfaces and improve performance.

## IMPORTANT

In solving this challenge, you may create a program which does not actually run. While the challenge still grades as intended, the technique may require additional work to use in practice. You may complete this challenge in the hosted environment.

## Background

Detecting malware by known signatures is a common practice. However, while signatures can be useful to protect against more basic threats, they only alert on known matches. 

In this challenge, you will need to defeat rudimentary signature detection. There are **10** signatures being detected in this challenge. You must break at least **2** of these.

For the purposes of scoring this challenge, the modified payload must retain at least **3** of its signatures.

## Getting Started

On the desktop, in the **prescup-b5-r1** directory, there are three scripts:

1. generate_raw_binary.sh

2. assemble_payload.sh

3. upload_file.sh

Open a terminal in this directory and run `generate_raw_binary.sh`. It will take 10-15 seconds, and then prompt for a `sudo` password. Enter the password listed below, and the file `asm_code.asm` will be generated.

Next, modify `asm_code.asm` with modified or additional instructions as you see fit, in order to bypass detection.

When you are done, run `assemble_payload.sh` to generate `payload.exe`. This command may also prompt for a `sudo` password.

Finally, run `upload_file.sh`. If you've modified the assembly enough to break up a few signatures, you will receive a submission token. Otherwise, you will be told whether you have not broken enough signatures, or if you've broken too many of them.

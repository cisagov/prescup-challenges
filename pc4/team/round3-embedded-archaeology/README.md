# Embedded Archaeology

An embedded device was recovered from an abandoned alien base. Its appearance is similar to devices typically issued by ISP routers. Since the device wasn't functioning, we desoldered its NAND flash chip and captured the contents into a file. NAND flash will develop bit errors over time due to repeated erasure and writing. Also, desoldering and content enumeration may have introduced additional bit errors.

Analyze the contents of this chip, replicate and apply its error correction code (ECC) implementation to fix any errors, and provide usable intelligence for when similar devices are recovered in the field.

**NICE Work Roles**
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst)
- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/data-analyst)

**NICE Tasks**
- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0049) - Decrypt seized data using technical means.
- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0286) - Perform file system forensic analysis.
- [T0287](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0287) - Perform static analysis to mount an "image" of a drive (without necessarily having the original drive).
- [T0404](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0404) - Utilize different programming languages to write code, open files, read files, and write output to different files.

## Background

NAND flash chips trade reliability for significantly increased density as compared to older Flash storage technologies (e.g., NOR). As such, blocks will develop errors over time, which lead to designs allowing for "spare" storage and built-in error-correction features.

Depending on a NAND flash device's page size, an additional number of "out-of-band" (OOB) bytes are included to store arbitrary information
that may help work around errors, recover from errors, or mark a page as unusable once it incurs damage exceeding a recoverable limit. Typical
sizes of OOB areas are (in bytes):

|               |              |
|--------------:|-------------:|
| **Page Size** | **OOB Size** |
|           512 |           16 |
|          1024 |           32 |
|          2048 |           64 |

Due to the nature of NAND flash, "clean" or "erased" storage areas consist entirely of `0xFF` data bytes. Writing to NAND flash occurs one page at a time, and can only "turn off" bits from an initial value of `1` to `0`.

To *set* a bit from `0` to `1`, an entire *erase block* or *sector* (containing multiple pages) must be erased (i.e., re-set to all-`0xFF` values) and re-written with new data--one page at a time. Erase blocks typically contain a power-of-two number of individual pages (e.g., 64).

When a page becomes unusable, the entire erase block containing it is marked "bad." Almost *all* brands and sizes of NAND flash will set the *first* OOB
byte of the *first* page in an erase block to a non-`0xFF` value to indicate a bad block. Additional pages within a block might also be marked in a similar
way, for redundancy, as indicated by each specific chip's datasheet.

Many modern NAND flash chips contain built-in, on-chip ECC features. However, these features tend to differ across manufacturers. This discourages embedded system vendors from using them. Implementing error correction in software -- or in a dedicated hardware flash-controller module -- _and_ using OOB bytes to store ECC data protecting each page's contents gives the vendor the flexibility of sourcing NAND flash chips of the same capacity from different manufacturers.

Because the *first* OOB byte in *some* of the pages is reserved for marking a bad erase block software-based ECC schemes skip at least the first OOB byte in *every* page for consistency.

The most popular ECC algorithm in use with NAND flash storage is BCH (Bose-Chaudhuri-Hocquenghem). In practice, it is applied to "slices" of
512, 1024, or 2048 bytes of a page. Corresponding "slices" of the OOB page are dedicated to storing the matching ECC bytes.

Very briefly:

Given parameters ***m*** and ***t*** the BCH algorithm is capable of correcting up to ***t*** bit flips in a "code word" of size up to **(2<sup>*m*</sup> - 1)** bits. This includes both the actual data payload *and* the redundant ECC overhead bits. To implement BCH, developers typically adapt `lib/bch.c` from the Linux kernel source code, or use Python's `bchlib` module. (Python's `bchlib` module is itself a wrapper around the Linux BCH implementation.) 

For each value of ***m***, Linux provides an implicit default *primitive polynomial* (several equivalent polynomials exist for each value of ***m***). The Python
`bchlib` implementation expects a polynomial *instead* of ***m*** (and derives ***m*** to match the provided polynomial). The following table shows the polynomials used by Linux for a relevant range of values of ***m***. You may assume these are the values used by the designers of the recovered artifact.

|         |               |
|--------:|--------------:|
| ***m*** | **Prim.Poly** |
|       5 |          0x25 |
|       6 |          0x43 |
|       7 |          0x83 |
|       8 |         0x11d |
|       9 |         0x211 |
|      10 |         0x409 |
|      11 |         0x805 |
|      12 |        0x1053 |
|      13 |        0x201b |
|      14 |        0x402b |
|      15 |        0x8003 |

#### Note 1

When seeking additional information on BCH, focus on how ***m*** and ***t*** influence how much data can be protected with how many bytes worth of ECC material.

#### Note 2

The stored ECC data corresponding to *uninitialized* (all-`0xFF` bytes) page data should *also* consist of all-`0xFF` bytes! This avoids the need to *gratuitously* touch each and every otherwise-empty page's OOB area. The typical approach is to apply an XOR byte mask to the calculated ECC bytes before writing them out *to* flash, and before using them, to verify and correct data immediately after reading *from* flash. For example: if the ECC bytes for data chunk `0xffffffff` end up being `0xbeef`, the XOR mask would be `0x4110`, ensuring that the *stored* ECC information for data `0xffffffff` would be `0xffff`.

## Getting Started

Your team has access to a  Kali user workstation which may be used to study and analyze the captured NAND flash data (**K9F1G08U0B.bin.gz**), available in-game from `http://challenge.us/files`. This should decompress to a file (**K9F1G08U0B.bin**) of a size equal to `(2048+64)*65536=138412032` bytes, representing the embedded device's full NAND flash chip (page + OOB data) storage.

The data sheet for the recovered chip is provided as **K9F1G08U0B-PCB0T00.pdf**. 

**linux-6.0.3.tar.xz**  is the Linux Source Tree.

Assume the BCH ECC parameters were chosen to maximize the number of correctable bits on each NAND flash page. Assume the primitive polynomial is one of the defaults also used in the Linux kernel, and that bits within data and ECC bytes are ***not*** swapped.

## Submissions

Provide the answers to three questions about this embedded device:

1. The **email address** of the account used to build the active boot kernel on the embedded device. E.g. running `sudo dmesg | grep 'Linux version'` on the `kali` machine produces `devel@kali.org`.
2. The **clear text password** of the provider-side device management account named `vendoradm`.  This account is a "back door" account included on the device by the vendor.
3. The **decoded value** of the encoded secret key for API access (`etc/secret_key*`) as a 32-hex-character string. The file system mounted by the kernel when the embedded device boots contains this secret key.

## Challenge Questions

1. What is the email address of the account used to build the current boot kernel? (would be displayed as part of `dmesg | grep 'Linux version'`)  
2. What is the (clear-text) password of the `vendoradm` account?  
3. What is the value of the decoded secret API key (found in `/etc/secret_key*` when the device is up and running)?

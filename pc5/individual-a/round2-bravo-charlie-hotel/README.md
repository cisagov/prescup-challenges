# Bravo Charlie Hotel

Recover content of a NAND Flash chip fragment by applying BCH error correction.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/): Decrypt seized data using technical means.
- [T0179](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform static media analysis.
- [T0228](https://niccs.cisa.gov/workforce-development/nice-framework/): Store, retrieve, and manipulate data for analysis of system capabilities and requirements.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/): Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

### NAND Flash Storage

While quite cost effective, high-density NAND Flash storage is prone to developing bit errors over time. Most chips contain additional "spare" storage designed to hold error correcting codes (ECC) that can help recover damaged information up to a certain point.

Initially, an "empty" NAND Flash chip has all bits set to logic 1 (all bytes on the device are set to `0xFF`). Devices are written one *page* at a time; a typical page is 2048 bytes in size, with an additional 64 bytes of spare, or "out-of-band" (OOB) storage associated to each page.

A write operation can only "turn off" bits that start at logic 1. To turn a logic 0 bit back to logic 1, an *erase* operation is needed. Erasure occurs over *multiple* (typically 64) pages, referred to as a *sector* or an *erase block*. During an erase operation, all data contained
in all 64 pages (2048+64 total bytes per page) in an erase block is set to `0xFF` in bulk. Once the entire block or sector is erased, individual pages can be written (by turning bits to logic 0) once again. An example of the logical layout of a NAND Flash block is shown in the following figure:

![](solution/img/nand_flash_layout.png)

When the NAND Flash chip develops persistent errors, the entire sector is marked as "bad" by storing a value *other* than `0xFF` in the first OOB byte of the sector's first and second pages. Because of this, it is common practice to have the first OOB byte in *all* pages across the entire device treated as "reserved" and never used for storing additional data or ECC recovery material.

### BCH Error Correction

ECC is implemented in software or in dedicated flash-controller hardware, using OOB to explicitly store the ECC material. This allows embedded vendors the flexibility to transparently switch between multiple vendor's NAND Flash storage chips of the same capacity.

Currently, the most popular ECC algorithm used with NAND Flash storage is BCH (Bose-Chaudhuri-Hocquenghem). Given parameters ***m*** and ***t***, BCH can correct up to ***t*** bit flips over a "code word" of up to **n = (2<sup>*m*</sup> - 1)** bits in size. By "code word" we mean a bit vector that includes both the data payload, and the ECC material used to detect and correct any transmission errors. For reference, ***m*** is known as the *Galois field order*, and ***t*** is the maximum error correction capability, in bits.

When implementing BCH, developers typically use the code freely available as part of the Linux kernel, either as a slightly adapted pair of `bch.[c|h]`files (if using the C language), or by installing `python-bchlib` (a wrapper around the Linux kernel C code for use with Python). Sample code demonstrating the initialization and use of BCH to produce ECC material and use it to remedy bit errors is provided using C and Python (see the `bch-saples.tar.gz` handout file).

### Storing ECC in NAND Flash

Once appropriate values for ***m*** and ***t*** are chosen, ECC byte values corresponding to the data in each page will be stored in the page's OOB area.

There is a potential problem: the ECC material computed by BCH to protect an uninitialized page (consisting of all `0xFF` bytes) is itself very unlikely to consist of all `0xFF` bytes! If we left it at that, an uninitialized flash chip would have to be "formatted" by writing lots of such
non-`0xFF` ECC byte sequences into *each* and *every* one of its uninitialized OOB areas! This is wasteful and adds wear-and-tear to the NAND Flash chip.

The typical solution is to apply an XOR mask to the ECC bytes before writing them to a page's OOB, and after reading them back in from the chip. The only purpose of this mask is to ensure that empty (all-`0xFF`) data is protected by all-`0xFF` ECC bytes as written out to disk, ensuring that uninitialized pages and blocks are "correct" out of the box, when both the
data and OOB (presumably storing ECC material) are initialized to `0xFF`.

#### Example:

For example, let's use *m=9* and *t=7* to protect a 32-byte data buffer with 8 bytes of ECC material.

After receiving values for the *m* and *t* parameters, the `bch_init` method will calculate *n* (the total number of bits in the code word), and *ecc_bits* (the portion of the code word that must be dedicated to ECC in order to be able to correct up to *t* bit flips).

In our case, *n=511* (63 full bytes and 7 bits), and the math of the BCH algorithm will determine that 63 ECC bits are needed to correct a maximum of *t=7* bit flips over the entire 511-bit code word. This leaves 511-63=448 bits of the code word available to transmit actual useful (payload) data.

Rounding to full bytes, we need 8 ECC bytes, and can protect up to 56 bytes of payload data with the given parameters.

We are free to transmit *less* data (e.g., 32 bytes in this example), with the unused data bits being implicitly assumed to be 0 on both the transmitting and receiving end.

If our data consists of an "uninitialized" NAND Flash buffer (of 32 all-`0xFF` bytes), it would be protected by the following 8 ECC bytes (as calculated by the provided `bch_demo` program):

```
BF 04 FA C8 F5 88 58 18
```

However, we prefer to store those 8 bytes on the FLASH chip as:

```
FF FF FF FF FF FF FF FF
```

...to match the uninitialized (all-`0xFF`) data bytes, and avoid the need to gratuitously initialize ECC bytes to match uninitialized data. Therefore, before writing out ECC bytes for *any* data, we should apply the following XOR mask:

```
40 FB 05 37 0A 77 A7 E7
```
Conversely, when reading data and ECC bytes *from* the flash chip, we should apply the above XOR mask to the ECC bytes *before* utilizing them to verify and correct the data!

## Getting Started

You are given one sector (erase block) from a larger original NAND Flash chip. The sector consists of 64 pages; each page is 2048 bytes in size, and has an additional 64 bytes of per-page OOB storage. As mentioned above, the first OOB byte in each page ***must*** be reserved and set to `0xFF`, to indicate the block has *not* been marked as "bad".

Download the relevant artifacts from `challenge.us`:

- `bch.tar.gz`: the BCH library to link against if you plan on using C.
- `python-bchlib.tar.gz`: Python version of BCH library. *Note: Run `pip install .`  from the unpacked `python-bchlib` folder to install; do not attempt to `pip install python-bchlib` directly, as the currently published version does not support the version of Python (3.11) available on your `kali` machine.*
- `bch-samples.tar.gz`: Sample programs showing how to initialize and use BCH, in either C or Python.
- `handout.bin`: The (damaged) NAND Flash sector containing the data to be recovered.

### Hint!

It is possible (and quite common in practice) to further subdivide a NAND Flash page (and its corresponding OOB area) into equal "sub-pages" or chunks to improve error correction capability.

For example: given that we must protect 2048 data bytes with up to 63 ECC bytes, we could pick ***m=15*** and ***t=33***, which can protect up to 4034 data bytes using 62 bytes of ECC material. All bytes in excess of 2048 are treated as implicit 0's by the BCH algorithm. This allows for up to ***t=33*** correctable bit errors to occur within each page.

However, picking ***m=14*** and ***t=17***, we can protect up to 2018 data bytes with 30 ECC bytes. If we split the 2048 data bytes into two chunks of 1024 bytes each, and apply BCH to each chunk using 30 out of the 63 available bytes of OOB, we can correct 17 erroneous bits in each *half* of the data, for a total of 34 correctable bits per page, using only 60 instead of 62 OOB bytes.

It may be possible to get an even better "correctable bits to ecc bytes" ratio by dividing the 2048 byte page and its available OOB area into *four* chunks of 512 data bytes each. The BCH parameters and chunk size used with `handout.bin` were chosen such that the number of total correctable bits over an entire page is maximized.

### Questions

Here are the questions you will have to answer with some additional detail.

1. How many pages of the provided sector (erase block) are in use?
2. How many OOB bytes per page (out of 64) are utilized for storing ECC data?
3. What combination of ***m***:***t*** maximizes the per-page error correction capability? Consider the possibility that pages and their OOB are sub-divided into chunks.
4. What is the XOR mask applied to a single chunk's ECC bytes during on-chip storage (to ensure uninitialized, all-`0xFF` data is stored with "uninitialized" all-`0xFF` ECC material on the NAND-Flash chip)?
5. What is the email address of user Lisa Bradshaw? Use BCH to correct any existing errors in `handout.bin`, then find and submit the email address for Lisa Bradshaw (Note that a valid email address can't contain commas, spaces, colons, semi-colons, brackets, parentheses, or other such delimiters).

## Challenge Questions

1. How many pages of the provided sector are in use?
2. How many OOB bytes per page (out of 64) are utilized for ECC?
3. What combination of m:t maximizes per-page error correction capability (hint: consider chunking)?
4. What is the XOR mask applied to a single chunk's ECC bytes during on-chip storage?
5. What is the email address of user Lisa Bradshaw?

# Ubi Ex Cavo

Extract information from a NAND Flash image recovered from an embedded device.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework): Decrypt seized data using technical means.
- [T0179](https://niccs.cisa.gov/workforce-development/nice-framework): Perform static media analysis.
- [T0228](https://niccs.cisa.gov/workforce-development/nice-framework): Store, retrieve, and manipulate data for analysis of system capabilities and requirements.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework): Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the [NAND Flash image](https://presidentscup.cisa.gov/files/pc5/teams-round2-ubi-ex-cavo.zip). The zipped file is ~7 MBs and the extracted NAND Flash image file is 128 MBs.

## Background

Analyze a NAND Flash image recovered from a 128 MB chip with 2048 byte data pages grouped into 1024 64-page  sectors (i.e., "erase blocks").

### NAND Flash Storage

Initially, an "empty" NAND Flash chip has all bits set to logic 1. All bytes on the device are set to `0xFF`. Devices are written one page at a time; a typical page is 2048 bytes in size, with an additional 64 bytes of spare "out-of-band" (OOB) storage associated to each page.

A write operation can only "turn off" bits that start at logic 1. To turn a logic 0 bit back to logic 1, an erase operation is needed. Erasure occurs over multiple (typically 64) pages, referred to as a *sector* or *erase block*. During an erase operation, all data contained in all 64 pages (2048+64 total bytes per page) in an erase block is set to `0xFF` in bulk. Once the entire block or sector is erased, individual pages can be written (by turning bits to logic 0) once again.

### Linux NAND Simulator

The Linux kernel contains a NAND Flash simulator in the form of a loadable module, `nandsim`. Various sizes and configurations of NAND Flash can be simulated by providing the module with a specific model's ID bytes: the bytes returned by the "Read ID" (0x90) command, as specified in the chip's data sheet (see *K9F1G08U0B-PCB0T00.pdf*, page 34). To simulate the 128 MB chip with 2048-byte pages and 64-page erase blocks, use:

```bash
sudo modprobe nandsim id_bytes=0xec,0xf1,0x00,0x95,0x40
```
This simulates the NAND Flash chip -- you are to analyze its recovered data as a single 128 MB partition.

Additionally, `nandsim` accepts a `parts=` option allowing the simulation of multiple partitions laid out over the full extend of the NAND Flash chip. 

For example:

```bash
sudo modprobe nandsim id_bytes=... parts=20,30
```
would create *three* partitions: `/dev/mtd0` spanning 20 erase blocks; `/dev/mtd1` spanning 30 erase blocks;  and `/dev/mtd2` spanning the remaining available storage, or 974 erase blocks.

### UBI Filesystem Layer

One of the partitions on the provided NAND Flash image is formatted with the UBI filesystem. Using `sudo`, load the `ubi` kernel module, then use various UBI filesystem tools (e.g., `ubiscan`, `ubiattach`) to set up the partition so you can `mount` its filesystem layer for further examination.

Consult these resources for additional details:

- `www.linux-mtd.infradead.org/faq/nand.html`
- `www.linux-mtd.infradead.org/faq/ubi.html`
- `www.linux-mtd.infradead.org/faq/ubifs.html`

## Getting Started

In the gamespace, browse to `challenge.us` and download:

- **K9F1G08U0B-PCB0T00.pdf:**  data sheet for the NAND Flash chip model from which the data was recovered.    
- **k9f1g08u0b_nand_flash_data.bin:** 128 MB image recovered from an embedded device.

> **Hint!**: Ignore any OOB bytes (not included in the recovered image) and ECC considerations (assume the recovered handout has no bit errors).

Your goal is to recover relevant information from this image and answer the challenge questions.

**NOTE:** Please make sure to use the word list attached as an ISO image to
your Kali workstation for any password cracking needs!

## Challenge Questions

1. How many partitions are configured on the NAND Flash image?
2. What is the offset (in 128K erase blocks) of the UBI partition?
3. What is the size (in bytes) of the UBI volume ID (VID) header?
4. What is the current password of admin user `chuck`?
5. What is the content of the `secret.hex` file?

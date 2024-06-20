# Ubi Ex Cavo

*Solution Guide*

## Overview

*Ubi Ex Cavo*  requires competitors to understand how NAND Flash storage is used by embedded devices to extract data from a recovered image.

## Question 1

*How many partitions are configured on the NAND Flash image?*

Generally, the nonvolatile boot media for an embedded system contains a device tree blob (DTB) which specifies the entire hardware map of the system. Find it (and its starting offset within the image) using the `binwalk` utility:

```bash
$ binwalk k9f1g08u0b_nand_flash_data.bin | grep -i 'device tree'

2396336      0x2490B0       Flattened device tree, size: 4410 bytes, version: 17
```

Carve out the DTB and the rest of the blobs identified by `binwalk`:

```bash
binwalk -M --dd=".*" k9f1g08u0b_nand_flash_data.bin
```

This creates a folder named `_k9f1g08u0b_nand_flash_data.bin.extracted`, with files named after the offset of each identified blob. We can now decompile the DTB, converting it into a "device tree source" (DTS) file:

```bash
$ dtc -I dtb -O dts _k9f1g08u0b_nand_flash_data.bin.extracted/2490B0

...
	partitions {
		compatible = "fixed-partitions";
		#address-cells = <0x01>;
		#size-cells = <0x01>;

		bitstream@0 {
			label = "bitstream";
			reg = <0x00 0x200000>;
			read-only;
		};

		firmware@200000 {
			label = "firmware";
			reg = <0x200000 0x20000>;
			read-only;
		};

		bootconf@220000 {
			label = "bootconf";
			reg = <0x220000 0x20000>;
		};

		kernel@240000 {
			label = "kernel";
			reg = <0x240000 0x1280000>;
		};

		ubi@14C0000 {
			label = "ubi";
			reg = <0x14c0000 0x6b40000>;
		};
	};
...
```

This shows we have a total of five partitions on the NAND Flash chip. `5` is the correct answer to Question 1.

## Question 2

*What is the offset (in 128K erase blocks) of the UBI partition?*

Partition sizes are a multiple of the *sector* or *erase block* size. According to the data sheet, our device has 2048-byte pages grouped into erase blocks of 64 pages each.

According to the device tree data from Question 1, the `ubi` partition starts at byte offset `0x14c0000` (or 21757952). If we divide that by 2048·64=131072, we get the offset in sectors or erase blocks, which is 166.

`166` is the correct answer to Question 2.

## Question 3

*What is the size (in bytes) of the UBI volume ID (VID) header?*

The easiest way to analyze the `ubi` partition is using the Linux kernel's NAND Flash simulator (`nandsim`) with the `ubi` filesystem driver and UBI-specific utilities from the `mtd-utils` package.

When loading `nandsim` with the parameters required to simulate our NAND Flash device (`id_bytes=0xec,0xf1,0x00,0x95,0x40`), specify a list of partition sizes (in units of erase blocks). The command to simulate the given NAND Flash chip with the partition layout provided in the DTS is:

```bash
sudo modprobe nandsim id_bytes=0xec,0xf1,0x00,0x95,0x40 parts=16,1,1,148
```
Note that the last partition size is implicit (i.e., "the remaining 858 erase blocks on the device"). The success of this operation is reflected in the `dmesg` output:

```bash
$ dmesg

...
 Creating 5 MTD partitions on "NAND 128MiB 3,3V 8-bit":
 0x000000000000-0x000000200000 : "NAND simulator partition 0"
 0x000000200000-0x000000220000 : "NAND simulator partition 1"
 0x000000220000-0x000000240000 : "NAND simulator partition 2"
 0x000000240000-0x0000014c0000 : "NAND simulator partition 3"
 0x0000014c0000-0x000008000000 : "NAND simulator partition 4"
```

...and by the presence of a list of `/dev/mtd*` devices reflecting each partition:

```bash
$ ls -al /dev/mtd?

crw------- 1 root root 90, 0 Jun 14 17:03 /dev/mtd0
crw------- 1 root root 90, 2 Jun 14 17:03 /dev/mtd1
crw------- 1 root root 90, 4 Jun 14 17:03 /dev/mtd2
crw------- 1 root root 90, 6 Jun 14 17:03 /dev/mtd3
crw------- 1 root root 90, 8 Jun 14 17:03 /dev/mtd4
```

Unfortunately, `nandsim` doesn't  support automatically "carving" the 128 MB image into the configured partitions. We must do that manually -- before loading each relevant partition's data into the simulator individually. Since we are only interested in the `ubi` partition, we only need:

```bash
$ sudo dd if=k9f1g08u0b_nand_flash_data.bin of=/dev/mtd4 bs=131072 skip=166

858+0 records in
858+0 records out
112459776 bytes (112 MB, 107 MiB) copied, 0.148364 s, 758 MB/s
```

Next, let's load the UBI kernel driver, and inspect `/dev/mtd4`:

```bash
$ sudo modprobe ubi

$ sudo ubiscan /dev/mtd4

Summary
=========================================================
mtd    : 4
type   : nand
size   : 112459776 bytes (107.2 MiB)
PEBs   : 858
min I/O: 2048 bytes
...
```
The noteworthy information is the minimum I/O unit size of 2048 bytes (matching the NAND Flash chip page size). Based on this, we deduce that the UBI volume ID header offset (VID) is also 2048 bytes as opposed to the default 64 bytes hard-coded in the tools, probably stemming from the original page size of earlier, smaller NAND Flash chips.

`2048` is the correct answer to Question 3.

## Question 4

*What is the current password of admin user `chuck`?*

The obvious shortcut of running `strings` on `k9f1g08u0b_nand_flash_data.bin`and grepping for `chuck` to find password hashes could easily backfire because multiple blocks might contain obsolete (overwritten) versions of the shadow file. To get the *current* version of Chuck's shadow entry, we must mount the UBI partition and dump the shadow file's contents:

```bash
$ sudo ubiattach -m 4 -O 2048

...

$ ls -al /dev/ubi*

crw------- 1 root root 246,   0 Jun 14 17:37 /dev/ubi0
crw------- 1 root root 246,   1 Jun 14 17:37 /dev/ubi0_0
crw------- 1 root root  10, 121 Jun 14 17:33 /dev/ubi_ctrl

$ sudo mount /dev/ubi0_0 /mnt

$ find /mnt -name shadow

/mnt/upper/etc/shadow

$ grep chuck /mnt/upper/etc/shadow 

chuck:$1$sgRNJB2C$b04mrqZzVHXWsljdtwX6K1:0:0:99999:7:::
```
Running the resulting line through `John` will produce the expected cleartext password:

```bash
john --wordlist=/media/cdrom/wordlist.txt --users=chuck /mnt/upper/etc/shadow
```

## Question 5

*What is the content of the `secret.hex` file?*

```bash
$ find /mnt -name secret.hex

/mnt/upper/etc/secret.hex

$ cat /mnt/upper/etc/secret.hex
...
```

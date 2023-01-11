# Embedded Archaeology

_Solution Guide_

## Overview

Randomized answers are generated during challenge deployment. This solution guide covers the walk-through and is organized by submission question. Analyze the contents of the chip, replicate and apply its error correction code (ECC) implementation to fix any errors, and provide usable intelligence for when similar devices are recovered in the field. 

## Question 1

_What is the email address of the account used to build the current boot kernel? (would be displayed as part of `dmesg | grep 'Linux version'`)_

### Initial inspection of `K9F1G08U0B.bin`

Download and unzip `K9F1G08U0B.bin.gz` and the datasheet `K9F1G08U0B-PCB0T00.pdf`. According to the datasheet, the chip contains 65536 pages of 2048 data and 64 OOB bytes each. Pages are grouped in 64-page sectors (referred to as *erase blocks*).

Eye-balling the data (using Python, `hexdump`, `hexedit`, or any other visualization tool), we notice bytes `2048-2051` of each page (first four bytes of the OOB area) are *always* set to `0xFF`, across the entire chip's contents. This tells us that for every page's `2048` bytes of data, only (the last) `60` (out of `64`) bytes of the OOB area are used for ECC.

Running `strings` on the image, and looking for `Linux version`, we get a few instances of:

```
$ strings K9F1G08U0B.bin | grep -i 'linux version'
Linux version 6.1.0-rc1-00046-g95e2e25680b0 (crash.t.dummy@ship.net.slx)
(riscv64-unknown-linux-gnu-gcc (g5964b5cd727) 11.1.0, GNU ld (GNU Binutils) 2.37) # SMP 
```

Similarly, looking for `BootKernel`, we get:

```
$ strings K9F1G08U0B.bin | grep -i 'bootkernel'
xBootKernel=A
```

> **Beware**, however, that this information is unreliable, since we *know* the image suffers from subtle errors, so we should not yet trust any of it!

Further inspection of `K9F1G08U0B.bin` using `binwalk` shows us another interesting piece of the puzzle:

```
$ binwalk K9F1G08U0B.bin | grep 'Flattened device tree'
2471208     0x25B528      Flattened device tree, size: 4575 bytes, version: 17
...
```

If we try to carve out the device tree blob, and decompile it, we error out:

```
$ binwalk -M --dd=".*" K9F1G08U0B.bin

$ dtc -I dtb -O dts _K9F1G08U0B.bin.extracted/25B528
FATAL ERROR: String offset -1073545163 overruns string table
```

This is due to either bit errors, or the interleaved OOB data present in the image. Either way, we'll have to find a way to apply BCH correction to the
data, and strip off the OOB bytes, before being able to proceed.

### Determining the BCH encoding parameters

We know that BCH is used, and we know that the number of correctable bit errors per `2048`-byte page is maximized. We also know that `60` bytes worth of BCH ECC information are associated with each `2048` bytes worth of data. Finally, we have the option of applying ECC on power-of-two "chunks" of a page, as follows:

| Chunks per page | Chunk bytes | OOB bytes |
|----------------:|------------:|----------:|
|               4 |         512 |        15 |
|               2 |        1024 |        30 |
|               1 |        2048 |        60 |

We have the option of using either the Python `bchlib` library, available via:

```
$ pip install bchlib
```

(which is, ultimately, a wrapper around the Linux kernel BCH implementation), or the kernel implementation directly, available in `lib/bch.c` and `include/linux/bch.h` in the Linux source tree (see the Appendix for full details). Since the author of this challenge prefers C over Python, the examples below will use C and link against a version of the kernel BCH code (very slightly modified to compile outside of the Linux kernel build process).

With (the slightly adapted) `bch.c` and `bch.h` from the Linux kernel in the `./bch/` folder, we need to determine the number of correctable bits we get from various combinations of BCH parameters $m$ (the Galois field order), and $t$ (the number of correctable bits per data "chunk"):

```
#include <stdio.h>
#include "bch/bch.h"

int main(int argc, char *argv[]) {
	struct bch_control *bch;
	int m, t, max_data, max_ecc, total_t;

	for (m = 9; m <= 15; m++)
		for (t = 2; t <= 40; t++) {

			bch = bch_init(m, t, 0, 0);
			if (bch == NULL)
				continue;

			max_data = (bch->n - bch->ecc_bits) / 8; // rounded down
			max_ecc = bch->ecc_bytes; // rounded up
			total_t = 0;

			if (max_data >=  512 && max_ecc * 4 <= 63)
				if (total_t < t * 4)
					total_t = t * 4;
			if (max_data >= 1024 && max_ecc * 2 <= 63)
				if (total_t < t * 2)
					total_t = t * 2;
			if (max_data >= 2048 && max_ecc <= 63)
				if (total_t < t)
					total_t = t;

			if (total_t > 0)
				printf("m=%2d t=%2d data=%3d ecc=%2d tt=%d\n",
					m, t, max_data, max_ecc, total_t);

			bch_free(bch);
		}

	return 0;
}
```

Without going into *too* many details on BCH, a "code word" (including data *and* ECC bits) is $2^m-1$ bits in size. If we know the precise number of ECC bits needed to allow for $t$ bit flips across the entire code word to be corrected, we can calculate the maximum number of bits in the code word that may be used to carry data (unused "data" bits in a code word do not need to be represented, and may implicitly be assumed to be `0`). 

The above program will print out all combinations of $m$ and $t$ where a `2048`-byte page (optionally split into chunks of `512` or `1024` bytes) can be protected by up to `63` bytes of ECC data (remember, the *first* OOB byte must be reserved as a bad-block marker). The `total_t` number shows the total number of correctable bits across all chunks making up the full `2048` byte page. After compiling and executing this program, we get:

```
m=13 t= 9 data=1009 ecc=15 tt=36
```

as our best option: four `512`-byte data chunks, each protected by `15` of a total of `60` ECC bytes, will get us `4 * 9 = 36` correctable bits per page.

This provides the highest "correctable bit density" of all alternatives. It also matches our observation: that for each `2048`-byte page, `4` OOB bytes are reserved, followed by `60` OOB bytes dedicated to storing ECC information.

### Calculating the XOR mask

Once we have determined the chunk size (`512` data bytes protected by `15` bytes of ECC) and BCH parameters ($m=13$, $t=9$), we must calculate an XOR mask to be applied to each ECC chunk before writing it out to physical flash. This ensures that uninitialized data chunks consisting of `512` bytes of `0xFF` will be "protected" by ECC data also consisting of only `0xFF` bytes, thus avoiding the need to gratuitously write non-`0xFF` data to an otherwise uninitialized page's OOB area. Consider the following C program:

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "bch/bch.h"

#define BCH_M      13
#define BCH_T       9

#define DATA_SIZE 512
#define ECC_SIZE   15

int main(int argc, char *argv[]) {
	struct bch_control *bch;
	uint8_t data[DATA_SIZE];
	uint8_t ecc[ECC_SIZE];
	int i;

	bch = bch_init(BCH_M, BCH_T, 0, 0);
	if (bch == NULL) {
		fprintf(stderr, "failed to initialize bch\n");
		return -1;
	}

	memset(data, 0xFF, DATA_SIZE);
	memset(ecc, 0x00, ECC_SIZE);
	bch_encode(bch, data, DATA_SIZE, ecc);

	bch_free(bch);

	printf("ecc_mask: ");
	for (i = 0; i < ECC_SIZE; i++)
		printf("0x%02x, ", ecc[i] ^ 0xff);
	printf("\n");

	return 0;
}
```

Running this program produces the following mask:

```
0xbe, 0x18, 0xf7, 0xd2, 0xae, 0x7b, 0xda, 0xa4, 0x45, 0x80, 0x2c, 0x14, 0x60, 0x1d, 0x87,
```

This mask should be presumed to have been applied to any and all `15`-byte ECC chunks before storing them on the flash chip. It will therefore need to be applied to all ECC chunks read *from* the flash image before using them to verify and correct any bit errors!

### Writing a BCH corrector program

Once again, this may be implemented in either Python (using `bchlib`), or in C with the following program:

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "bch/bch.h"

#define BCH_M      13
#define BCH_T       9

#define NSUBS       4

#define DATA_SIZE 512
#define PAD_SIZE    4
#define ECC_SIZE   15

typedef struct {
	uint8_t data[NSUBS][DATA_SIZE];
	uint8_t pad[PAD_SIZE];
	uint8_t ecc[NSUBS][ECC_SIZE];
} nand_page_t;

uint8_t ecc_mask[ECC_SIZE] = {
	0xbe, 0x18, 0xf7, 0xd2, 0xae, 0x7b, 0xda,
	0xa4, 0x45, 0x80, 0x2c, 0x14, 0x60, 0x1d, 0x87,
};

void apply_mask(uint8_t *ecc) {
	int i;
	for (i = 0; i < ECC_SIZE; i++)
		ecc[i] ^= ecc_mask[i];
}

int main(int argc, char *argv[]) {
	struct bch_control *bch;
	nand_page_t page;
	unsigned eloc[BCH_T];
	int pnum, nerr, i, j;

	bch = bch_init(BCH_M, BCH_T, 0, 0);
	if (bch == NULL) {
		fprintf(stderr, "failed to initialize bch\n");
		return -1;
	}

	for (pnum = 0;
	     read(STDIN_FILENO, &page, sizeof(page)) == sizeof(page);
	     pnum++)
		for (i = 0; i < NSUBS; i++) {
			apply_mask(page.ecc[i]);
			nerr = bch_decode(bch, page.data[i], DATA_SIZE,
					  page.ecc[i], NULL, NULL, eloc);
			if (nerr > 0)
				fprintf(stderr, "page %d chunk %d has %d "
					"correctable errors\n", pnum, i, nerr);
			if (nerr < 0)
				fprintf(stderr, "page %d chunk %d has "
					"uncorrectable errors\n", pnum, i);
			for (j = 0; j < nerr; j++)
				page.data[i][eloc[j] / 8] ^= 1 << (eloc[j] % 8);
			write(STDOUT_FILENO, page.data[i], DATA_SIZE);
		}

	bch_free(bch);

	return 0;
}
```

This program will apply BCH ECC correction to each page (one `512`-byte chunk at a time), and will then write out just the page data, stripping off the ECC information and `4`-byte padding.

> **Note:** We rightfully assume that, whether implemented in a dedicated flash controller (hardware) or in the kernel (software), our target embedded device lazily uses the same default BCH primitive polynomial as the standard Linux kernel, and that bits within each byte are *not* reversed. In real life, alternative polynomials of the same degree might have to be sought out (comprehensive lists are publicly available in various cryptography and mathematics papers), and the optional byte reversal flag might also have to be considered.

After running the corrector:

```
$ ./bch_fix < K9F1G08U0B.bin > K9F1G08U0B_clean.bin
```

The resulting file, `K9F1G08U0B_clean.bin`, will contain `2048 * 65536 = 134217728` bytes of data.

### Taking another look at the (corrected) data blob

Re-running `strings` on the now-corrected data-only blob, we get:

```
$ strings K9F1G08U0B_clean.bin | grep -i 'linux version'
Linux version 6.1.0-rc1-00046-g95e2e25680b0 (crash.t.dummy@ship.net.slx)
 (riscv64-unknown-linux-gnu-gcc (g5964b5cd727) 11.1.0, GNU ld (GNU Binutils) 2.37) # SMP 
...
Linux version 6.1.0-rc1-00046-g95e2e25680b0 (crash.u.dummy@ship.net.slx)
 (riscv64-unknown-linux-gnu-gcc (g5964b5cd727) 11.1.0, GNU ld (GNU Binutils) 2.37) # SMP 
...
```

and

```
$ strings K9F1G08U0B_clean.bin | grep -i 'bootkernel'
BootKernel=B
```

So, in hindsight, it's good we didn't rush to provide what appeared to be the answer earlier on, before applying ECC to the obviously corrupted data!

If we try to extract and decompile the device tree info again:

```
$ binwalk K9F1G08U0B_clean.bin
...
2396328     0x2490A8      Flattened device tree, size: 4575 bytes, version: 17
...
```
then proceed to extract and decompile the devicetree blob:

```
$ binwalk -M --dd=".*" K9F1G08U0B_clean.bin
...

$ dtc -I dtb -O dts _K9F1G08U0B_clean.bin.extracted/2490A8
```
we gain access to the entire hardware layout of our embedded device, and in particular to the partitioning layout of its NAND flash storage:

```
nandcs@0 {
        reg = <0x00>;
        compatible = "litex,nandcs";
        nand-bus-width = <0x08>;
        nand-ecc-algo = "bch";
        nand-ecc-strength = <0x09>;
        nand-ecc-step-size = <0x200>;

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

                kernelA@240000 {
                        label = "kernelA";
                        reg = <0x240000 0x1800000>;
                };

                kernelB@1a40000 {
                        label = "kernelB";
                        reg = <0x1a40000 0x1800000>;
                };

                ubi@3240000 {
                        label = "ubi";
                        reg = <0x3240000 0x4dc0000>;
                };
        };
};
```

This (somewhat belatedly) confirms our choice of $t=9$ and ECC data "chunk" size (`512 = 0x200` bytes). We are also given starting offsets and sizes for each partition comprising the NAND flash data. We note that partition sizes are a multiple of an *erase block* (`64 * 2048 = 131072 = 0x20000` bytes).

### Carving out flash partitions

We have the following list of partitions:

 - `bitstream` (16 erase blocks): presumably the embedded device is running on an FPGA board, and this partition contains the FPGA programming information needed to configure it as an embedded SoC.
 - `firmware` (1 erase block): presumably the "bios" first executed by the SoC, once the FPGA is configured as such by the bitstream.
 - `bootconf` (1 erase block): presumably tells the "bios" which of the two alternative kernels is active and should be loaded at boot (A or B). This
   determines the correct answer to the first question.
 - `kernelA` (192 erase blocks): the first of two alternative (Linux) kernels the embedded device may load, as determined by `bootconf`.
 - `kernelB` (192 erase blocks): the second of two alternative (Linux) kernels the embedded device may load, as determined by `bootconf`.
 - `ubi` (the remaining 622 erase blocks): likely a UBI image, probably containing additional filesystem(s) the kernel may mount during/after boot-up.

We use `dd` to carve out each flash partition:

```
$ dd if=K9F1G08U0B_clean.bin of=p0.bin bs=$((0x20000)) skip=0 count=16
$ dd if=K9F1G08U0B_clean.bin of=p1.bin bs=$((0x20000)) skip=16 count=1
$ dd if=K9F1G08U0B_clean.bin of=p2.bin bs=$((0x20000)) skip=17 count=1
$ dd if=K9F1G08U0B_clean.bin of=p3.bin bs=$((0x20000)) skip=18 count=192
$ dd if=K9F1G08U0B_clean.bin of=p4.bin bs=$((0x20000)) skip=210 count=192
$ dd if=K9F1G08U0B_clean.bin of=p5.bin bs=$((0x20000)) skip=402 count=622
```

At this point, we can find the answer to the first question of the challenge. By examining `p2.bin` (a.k.a. the `bootconf` partition), we can determine which kernel is currently configured as "active":

```
$ hexdump -C p2.bin
00000000  42 6f 6f 74 4b 65 72 6e  65 6c 3d 42 0a ff ff ff  |BootKernel=B....|
00000010  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
*
00020000
```

Next, we look for the email address associated with the "Linux version" string in `p4.bin` (a.k.a. the `kernelB` partition):

```
$ strings p4.bin | grep -i 'linux version'
...
Linux version 6.1.0-rc1-00046-g95e2e25680b0 (crash.u.dummy@ship.net.slx)
 (riscv64-unknown-linux-gnu-gcc (g5964b5cd727) 11.1.0, GNU ld (GNU Binutils) 2.37) # SMP 
...
```

The answer to Question 1 is `crash.u.dummy@ship.net.slx`.

## Question 2

_What is the (clear-text) password of the `vendoradm` account?_

### Inspecting the boot kernel

Using `binwalk`, we search for an `initramfs` image that might be built into the kernel as a `cpio` archive:

```
$ binwalk --extract p4.bin
...

$ file _p4.bin.extracted/*
_p4.bin.extracted/A0ECF0:     ASCII cpio archive (SVR4 with no CRC)
_p4.bin.extracted/C4FF20.lzo: lzop compressed data - version 0.000,
_p4.bin.extracted/CD3000.xz:  XZ compressed data, checksum NONE

$ cd _p4.bin.extracted

$ cpio -id < A0ECF0

$ cat etc/inittab
::sysinit:/bin/busybox mount -t proc proc /proc
::sysinit:/bin/busybox mount -t devtmpfs devtmpfs /dev
::sysinit:/bin/busybox mount -t tmpfs tmpfs /tmp
::sysinit:/bin/busybox mount -t sysfs sysfs /sys
::sysinit:/bin/busybox mount -t ubifs /dev/ubi0_0 /overlay -o rw,noatime,ubi=0,vol=0
::sysinit:/bin/busybox mount -t overlay overlayfs:/overlay / -o rw,noatime,lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work
::sysinit:/bin/busybox --install -s
/dev/console::sysinit:-/bin/ash
```

The `initramfs` image contains `busybox`, and an `etc/inittab` file used to set up the system. We notice it attempts to mount `/dev/ubi0_0` as an overlay
on top of the root directory. Interestingly enough, our last partition is named `ubi`, so it's probably where the overlay file system is stored.

### Using the `nandsim` NAND flash simulator and UBI kernel subsystem

The easiest way to inspect the `p5.bin` (a.k.a. `ubi`) partition is through the Linux kernel's `nandsim` flash simulator. To simulate our NAND flash chip (data portion only, no OOB), we need the sequence of bytes returned by the device's `Read ID` command (see page 26 of the datasheet, `K9F1G08U0B-PCB0T00.pdf`). We also have the option of providing `nandsim` with a sequence of partition sizes (all but the last one, whose size is implicitly calculated). To start `nandsim`, use the following command:

```
$ sudo modprobe nandsim id_bytes=0xec,0xf1,0x00,0x95,0x40 parts=16,1,1,192,192

$ sudo dmesg | tail -30
...
nand: Samsung NAND 128MiB 3,3V 8-bit
nand: 128 MiB, SLC, erase size: 128 KiB, page size: 2048, OOB size: 64
flash size: 128 MiB
page size: 2048 bytes
OOB area size: 64 bytes
sector size: 128 KiB
pages number: 65536
pages per sector: 64
...
flash size with OOB: 135168 KiB
...
Creating 6 MTD partitions on "NAND 128MiB 3,3V 8-bit":
0x000000000000-0x000000200000 : "NAND simulator partition 0"
0x000000200000-0x000000220000 : "NAND simulator partition 1"
0x000000220000-0x000000240000 : "NAND simulator partition 2"
0x000000240000-0x000001a40000 : "NAND simulator partition 3"
0x000001a40000-0x000003240000 : "NAND simulator partition 4"
0x000003240000-0x000008000000 : "NAND simulator partition 5"
...

$ ls -al /dev/mtd*
crw------- 1 root root 90,  0 Oct 28 13:48 /dev/mtd0
crw------- 1 root root 90,  1 Oct 28 13:48 /dev/mtd0ro
crw------- 1 root root 90,  2 Oct 28 13:48 /dev/mtd1
crw------- 1 root root 90,  3 Oct 28 13:48 /dev/mtd1ro
crw------- 1 root root 90,  4 Oct 28 13:48 /dev/mtd2
crw------- 1 root root 90,  5 Oct 28 13:48 /dev/mtd2ro
crw------- 1 root root 90,  6 Oct 28 13:48 /dev/mtd3
crw------- 1 root root 90,  7 Oct 28 13:48 /dev/mtd3ro
crw------- 1 root root 90,  8 Oct 28 13:48 /dev/mtd4
crw------- 1 root root 90,  9 Oct 28 13:48 /dev/mtd4ro
crw------- 1 root root 90, 10 Oct 28 13:48 /dev/mtd5
crw------- 1 root root 90, 11 Oct 28 13:48 /dev/mtd5ro
```

Unfortunately, `nandsim` can't automatically carve out partition data from the overall `K9F1G08U0B_clean.bin` file. If we wish to initialize a partition with data, we must do so manually:

```
$ sudo dd if=p5.bin of=/dev/mtd5
159232+0 records in
159232+0 records out
81526784 bytes (82 MB, 78 MiB) copied, 0.617786 s, 132 MB/s
```

Next, we'll need to load kernel support for UBI:

```
$ sudo modprobe ubi
```

We can now inspect `/dev/mtd5` for UBI details:

```
$ sudo ubiscan /dev/mtd5
...
min I/O: 2048 bytes
...
```

The important thing to note here is that the minimum I/O unit is `2048` bytes (a page of the NAND flash chip being used), which is a strong indication that the offset of the "UBI volume ID header" (or `VID header offset`) is `2048`, rather than the default `64` bytes hard-coded in the tool, probably dating back to a time when the most frequently encountered NAND flash page size used to be `64 bytes`. We must use this information when attaching the `ubi` partition (now available as `/dev/mtd5`) to the UBI subsystem:

```
$ sudo ubiattach -m 5 -O 2048
UBI device number 0, total 622 LEBs (78979072 bytes, 75.3 MiB),
  available 0 LEBs (0 bytes), LEB size 126976 bytes (124.0 KiB)

$ sudo dmesg | tail -11
ubi0: attaching mtd5
ubi0: scanning is finished
ubi0: attached mtd5 (name "NAND simulator partition 5", size 77 MiB)
ubi0: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes
ubi0: min./max. I/O unit sizes: 2048/2048, sub-page size 512
ubi0: VID header offset: 2048 (aligned 2048), data offset: 4096
ubi0: good PEBs: 622, bad PEBs: 0, corrupted PEBs: 0
ubi0: user volume: 1, internal volumes: 1, max. volumes count: 128
ubi0: max/mean erase counter: 1/0, WL threshold: 4096, image sequence number: 750031308
ubi0: available PEBs: 0, total reserved PEBs: 622, PEBs reserved for bad PEB handling: 20
ubi0: background thread "ubi_bgt0d" started, PID 15440

$ ls -al /dev/ubi*
crw------- 1 root root 247,   0 Oct 28 14:16 /dev/ubi0
crw------- 1 root root 247,   1 Oct 28 14:16 /dev/ubi0_0
crw------- 1 root root  10, 123 Oct 28 14:08 /dev/ubi_ctrl
```

All that remains to be done now is to mount `/dev/ubi0_0` and inspect the files it contains:

```
$ sudo mount /dev/ubi0_0 /mnt

$ ls /mnt/upper/etc
...

$ grep vendoradm /mnt/upper/etc/shadow    
vendoradm:$1$p0qnWJMX$917PAYE3m7Yj.voczATi41:0:0:99999:7:::

$ base64 -d /mnt/upper/etc/secret_key.b64
088012811959a0051f3366bf2ca9278a
```

Running the `vendoradm` pasword hash through `John` yields `marvelous`, the answer to the second question.

## Question 3

_What is the value of the decoded secret API key (found in `/etc/secret_key*` when the device is up and running)?_

The 32-character decoded `secret_key` string answers the third question. 

> **Note**: the third answer will be specific to each individual deployment of the challenge. The answer for the artifacts provided in this repository is: `d3b07384d113edec49eaa6238ad5ff00`


## Appendix: Extracting the BCH "library" from the Linux kernel

Most challengers will attempt solving this challenge using Python's `bchlib`. However, the sample solutions provided in this solution guide are written in C. This appendix shows how to adapt the BCH module available in Linux for stand-alone compilation and linking against the provided samples.

Start with:

```
$ wget -O - http://challenge.us/files/linux-6.0.3.tar.xz | tar xfJ -
$ mkdir bch
$ cp linux-6.0.3/lib/bch.c bch/
$ cp linux-6.0.3/include/linux/bch.h bch/
$ cp linux-6.0.3/include/asm-generic/bitops/fls.h bch/

$ sed -i '/EXPORT_/d' bch/bch.c
$ sed -i '/MODULE_/d' bch/bch.c
$ sed -i 's/u32/__u32/g' bch/bch.c
$ sed -i 's/u8/__u8/g' bch/bch.c
$ sed -i 's/kfree/free/g' bch/bch.c
$ sed -i 's/DIV_ROUND_UP/__KERNEL_DIV_ROUND_UP/' bch/bch.c
```

Finally, apply the following patch (`bch.patch`) to the `bch` folder:

```
diff '--color=auto' -u a/bch.c b/bch.c
--- a/bch.c	2022-10-28 15:52:30.823982108 -0400
+++ b/bch.c	2022-10-28 16:04:48.775972832 -0400
@@ -34,12 +34,6 @@
  * to bch_decode in order to skip certain steps. See bch_decode() documentation
  * for details.
  *
- * Option CONFIG_BCH_CONST_PARAMS can be used to force fixed values of
- * parameters m and t; thus allowing extra compiler optimizations and providing
- * better (up to 2x) encoding performance. Using this option makes sense when
- * (m,t) are fixed and known in advance, e.g. when using BCH error correction
- * on a particular NAND flash device.
- *
  * Algorithmic details:
  *
  * Encoding is performed by processing 32 input bits in parallel, using 4
@@ -65,28 +59,23 @@
  * finite fields GF(2^q). In Rapport de recherche INRIA no 2829, 1996.
  */
 
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <xorg/wacom-util.h> // for ARRAY_SIZE() macro
+#include <endian.h>
+#include <linux/types.h>
 #include <linux/kernel.h>
 #include <linux/errno.h>
-#include <linux/init.h>
 #include <linux/module.h>
-#include <linux/slab.h>
-#include <linux/bitops.h>
 #include <asm/byteorder.h>
-#include <linux/bch.h>
+#include "bch.h"
 
-#if defined(CONFIG_BCH_CONST_PARAMS)
-#define GF_M(_p)               (CONFIG_BCH_CONST_M)
-#define GF_T(_p)               (CONFIG_BCH_CONST_T)
-#define GF_N(_p)               ((1 << (CONFIG_BCH_CONST_M))-1)
-#define BCH_MAX_M              (CONFIG_BCH_CONST_M)
-#define BCH_MAX_T	       (CONFIG_BCH_CONST_T)
-#else
 #define GF_M(_p)               ((_p)->m)
 #define GF_T(_p)               ((_p)->t)
 #define GF_N(_p)               ((_p)->n)
 #define BCH_MAX_M              15 /* 2KB */
 #define BCH_MAX_T              64 /* 64 bit correction */
-#endif
 
 #define BCH_ECC_WORDS(_p)      __KERNEL_DIV_ROUND_UP(GF_M(_p)*GF_T(_p), 32)
 #define BCH_ECC_BYTES(_p)      __KERNEL_DIV_ROUND_UP(GF_M(_p)*GF_T(_p), 8)
@@ -97,23 +86,9 @@
 #define dbg(_fmt, args...)     do {} while (0)
 #endif
 
-/*
- * represent a polynomial over GF(2^m)
- */
-struct gf_poly {
-	unsigned int deg;    /* polynomial degree */
-	unsigned int c[];   /* polynomial terms */
-};
-
 /* given its degree, compute a polynomial size in bytes */
 #define GF_POLY_SZ(_d) (sizeof(struct gf_poly)+((_d)+1)*sizeof(unsigned int))
 
-/* polynomial of degree 1 */
-struct gf_poly_deg1 {
-	struct gf_poly poly;
-	unsigned int   c[2];
-};
-
 static __u8 swap_bits_table[] = {
 	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
 	0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
@@ -252,8 +227,11 @@
 	const uint32_t * const tab3 = tab2 + 256*(l+1);
 	const uint32_t *pdata, *p0, *p1, *p2, *p3;
 
-	if (WARN_ON(r_bytes > sizeof(r)))
+	if (r_bytes > sizeof(r)) {
+		fprintf(stderr, "WARNING: bch_encode: "
+			"r_bytes=%ld > sizeof(r)=%ld\n", r_bytes, sizeof(r));
 		return;
+	}
 
 	if (ecc) {
 		/* load ecc parity bytes into internal 32-bit buffer */
@@ -291,7 +269,7 @@
 	 */
 	while (mlen--) {
 		/* input data is read in big-endian format */
-		w = cpu_to_be32(*pdata++);
+		w = htobe32(*pdata++);
 		if (bch->swap_bits)
 			w = (__u32)swap_bits(bch, w) |
 			    ((__u32)swap_bits(bch, w >> 8) << 8) |
@@ -1219,7 +1197,7 @@
 {
 	void *ptr;
 
-	ptr = kmalloc(size, GFP_KERNEL);
+	ptr = malloc(size);
 	if (ptr == NULL)
 		*err = 1;
 	return ptr;
@@ -1330,14 +1308,6 @@
 		0x402b, 0x8003,
 	};
 
-#if defined(CONFIG_BCH_CONST_PARAMS)
-	if ((m != (CONFIG_BCH_CONST_M)) || (t != (CONFIG_BCH_CONST_T))) {
-		printk(KERN_ERR "bch encoder/decoder was configured to support "
-		       "parameters m=%d, t=%d only!\n",
-		       CONFIG_BCH_CONST_M, CONFIG_BCH_CONST_T);
-		goto fail;
-	}
-#endif
 	if ((m < min_m) || (m > BCH_MAX_M))
 		/*
 		 * values of m greater than 15 are not currently supported;
@@ -1362,7 +1332,7 @@
 	if (prim_poly == 0)
 		prim_poly = prim_poly_tab[m-min_m];
 
-	bch = kzalloc(sizeof(*bch), GFP_KERNEL);
+	bch = calloc(sizeof(*bch), 1);
 	if (bch == NULL)
 		goto fail;
 
diff '--color=auto' -u a/bch.h b/bch.h
--- a/bch.h	2022-10-28 15:32:51.227996936 -0400
+++ b/bch.h	2022-10-18 14:11:19.000000000 -0400
@@ -14,7 +14,22 @@
 #ifndef _BCH_H
 #define _BCH_H
 
+#include <stdint.h>
+#include <stdbool.h>
 #include <linux/types.h>
+#include "fls.h"
+
+/* represent a polynomial over GF(2^m) */
+struct gf_poly {
+	unsigned int deg;    /* polynomial degree */
+	unsigned int c[];   /* polynomial terms */
+};
+
+/* polynomial of degree 1 */
+struct gf_poly_deg1 {
+	struct gf_poly poly;
+	unsigned int   c[2];
+};
 
 /**
  * struct bch_control - BCH control structure
```

At this point, one may compile the BCH error correction sample program shown earlier in this document, named `bch_fix.c`, like so:

```
gcc -o bch_fix bch_fix.c bch/bch.c -Wall
```

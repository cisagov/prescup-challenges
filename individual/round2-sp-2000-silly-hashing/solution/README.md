<img src="../../../logo.png" height="250px">

# SillyHashing

## Solution


**NOTE**: the `sillyhash` binary depends on (is linked against) the Python3
runtime library.

The "flag" required to solve the puzzle is the command line input to `sillyhash`
that would produce a given hash, e.g.:

```
./sillyhash 'secret answer key'
a9e81478b786081e124e59a7c4993fdb067dfbd2b8b779f3c444fdbe3bec4819f57f7b6d299641a9803c675588886893
```

By either repeated trial-and-error, or by actual reverse engineering of the
binary, competitors would find out that the program splits up the input string
into three chunks of four characters each, padding with spaces if the input
string is shorter than 12 characters, and truncating excess input if longer than
12 characters. An `md5` hash is generated for each four-character substring, and
the three `md5` hashes are concatenated into the final output "silly hash".

Short of *guessing* the "silly hashing" scheme described above by observation,
competitors can derive it by reverse engineering the binary, using the following
sequence of steps:

**Step 1:** Run `strings` on the `sillyhash` binary. This would generate output
like:

```
...
/usr/bin/python3
;*3$"
import base64
eval(compile(base64.b64decode(b'
=='), '<string>', 'exec'))
gCpkCK0NXZnlGZ4VGaukSKngTLmRXdngSZk92YuVmLdJTM6gzWn5WayR3c51GK1QWbgACIgACIKsCIpgCdzV2ZpRGelhmLpkyJ40iZ0V3JoUGZvNmbl5SX4oDNbdmbpJHdzlXboUDZtBCIgACIgowKgkCK0NXZnlGZ4VGaukSKngTLmRXdngSZk92YuVmLdRjOws1Zulmc0NXethSNk1GK05WayBnCpcCInACLyEDK0NXdqxmLn5WayR3c51GI9AyZulmc0NXetpwJhM3dl5GIltWYmBycpBycphGdnASPgcmbpJHdzlXbgACIgogOlNHblpQXxsldnJXYg0DIn5WayR3c51GIgACIKoTKyASP+ASK2dmchhiblxGKgYWaKoQNk1GI0J3bw1WagIWash2chhGIt9mcmpgdnJXYgQncvBXbpByc5NHIt9mcmpgCz42boRXew9ibpJ2LyNXdvEyI
...

```

This indicates we're embedding a base64-encoded Python script inside our binary
to generate the actual "silly hash" string.

**Step 2:** Passing the *apparently* base64-encoded Python script through a
decoder (e.g., `base64 -d`) results in output that doesn't make much sense.
Therefore, it is worth running the `sillihash` binary through a debugger, or
disassembling it (using `objdump -D`). Doing so will show that the "base64"
string is being reversed by a deviously-named `strexec()` function, before being
concatenated with its neighbors and passed through the `PyRun()` C-library call.

**Step 3:** Reversing the `'gCpk...EyI'` string before submitting it to
`base64 -d` will yield:

```
from sys import argv
from hashlib import md5

if (len(argv) >= 2):
    mystring = argv[1]
else:
    mystring = 'this is fake news!'
mystring = mystring.ljust(12, ' ')
print(md5(mystring[0:4].encode('utf-8')).hexdigest() +
      md5(mystring[4:8].encode('utf-8')).hexdigest() +
      md5(mystring[8:12].encode('utf-8')).hexdigest())
```

which gives away all the information needed to understand the "silly hashing"
"algorithm".

**Step 4:** Once competitors realize the nature of the "silly hashing" scheme,
they will need to *brute force* the `md5` checksum. Luckily, the length of each
substring is limited to four characters, which makes it feasible to enumerate
all possible inputs within 10-20 minutes, using a shell script built around
`/bin/md5sum` or a C program like the following:

```
/*
 * gen_printable_md5.c
 *
 * generate all printable strings of given <width>, and their md5sum.
 *
 * compile: `gcc -o gen_printable_md5 gen_printable_md5.c -lcrypto -Wall`
 *
 * NOTE: takes somewhere around 12 minutes when width == 4, on a
 *       machine with "Intel(R) Xeon(R) CPU E5-1650 v2 @ 3.50GHz"
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/md5.h>

#define MAXWIDTH 10

void
gen_str(unsigned pos, unsigned width, unsigned char *buf)
{
	MD5_CTX c;
	unsigned char sum[MD5_DIGEST_LENGTH];
	int i;

	/* enumerate printable ascii from first (' ') to last ('~') */
	for (buf[pos] = ' '; buf[pos] <= '~'; buf[pos]++) {
		if (pos < width - 1) {
			gen_str(pos + 1, width, buf);
		} else {
			MD5_Init(&c);
			MD5_Update(&c, buf, width);
			MD5_Final(sum, &c);
			for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
				printf("%02x", sum[i]);
			}
			printf(" '%s'\n", buf);
		}
	}
}

int
main(int argc, char *argv[])
{
	unsigned char buf[MAXWIDTH + 1] = { '\0' };
	unsigned width;

	if (!(argc > 1 && (width = atoi(argv[1])) <= MAXWIDTH)) {
		fprintf(stderr,
			"\nusage: %s <width>\t(where width <= %d)\n\n",
			argv[0], MAXWIDTH);
		return 1;
	}

	gen_str(0, width, buf);
	return 0;
}
```

**Appendix:** Source code to the `sillyhash` program:

```
/*
 * run an embedded python script from within c
 *
 * compile:
 * `gcc -o sillyhash sillyhash.c -I/usr/include/python3.7m -lpython3.7m -Wall`
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>

char pre[] =  "import base64\neval(compile(base64.b64decode(b'";
char post[] = "=='), '<string>', 'exec'))";
/* NOTE: pstr[] reversed for extra "obfuscation" beyond base64 */
char pstr[] = "gCpkCK0NXZnlGZ4VGaukSKngTLmRXdngSZk92YuVmLdJTM6"
              "gzWn5WayR3c51GK1QWbgACIgACIKsCIpgCdzV2ZpRGelhmL"
              "pkyJ40iZ0V3JoUGZvNmbl5SX4oDNbdmbpJHdzlXboUDZtBC"
              "IgACIgowKgkCK0NXZnlGZ4VGaukSKngTLmRXdngSZk92YuV"
              "mLdRjOws1Zulmc0NXethSNk1GK05WayBnCpcCInACLyEDK0"
              "NXdqxmLn5WayR3c51GI9AyZulmc0NXetpwJhM3dl5GIltWY"
              "mBycpBycphGdnASPgcmbpJHdzlXbgACIgogOlNHblpQXxsl"
              "dnJXYg0DIn5WayR3c51GIgACIKoTKyASP+ASK2dmchhiblx"
              "GKgYWaKoQNk1GI0J3bw1WagIWash2chhGIt9mcmpgdnJXYg"
              "QncvBXbpByc5NHIt9mcmpgCz42boRXew9ibpJ2LyNXdvEyI";

char buf[1024] = { '\0' };

static char *
strexc(char *str)
{
	char *lo, *hi, t;
	if (str == NULL || str[0] == '\0')
		goto out;
	/* reverse the string: */
	for (lo = str, hi = str + strlen(str) - 1; hi > lo; lo++, hi--) {
		t   = *lo;
		*lo = *hi;
		*hi = t;
	}
out:
	return str;
}

int
main(int argc, char *argv[])
{
	wchar_t *prog, *py_argv[3] = { NULL };
	Py_SetProgramName((prog = Py_DecodeLocale("/usr/bin/python3", NULL)));
	Py_Initialize();
	if (argc >= 2) {
		py_argv[0] = Py_DecodeLocale(argv[0], NULL);
		py_argv[1] = Py_DecodeLocale(argv[1], NULL);
		PySys_SetArgv(2, py_argv);
	}
	strcat(buf, pre);
	strexc(pstr); /* reverse to obtain proper base64 encoded script */
	strcat(buf, pstr);
	strcat(buf, post);
	PyRun_SimpleString(buf);
	if (Py_FinalizeEx() < 0) {
		return 1;
	}
	PyMem_RawFree(prog);
	return 0;
}
```

<br><br>

Flag - `thisisurflag`


## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
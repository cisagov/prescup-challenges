# Hack to the Future

## Question 4

*Find the `lattice decoder`, discover the `shutdown` phrase, and execute the binary to destroy the `Farsight XR20`.*

### Analysis

The challenge description for the Future era is intentionally sparse: "No starting hints are provided." We're told to SSH into `perfectdark.fut.pccc` and forensically investigate to recover the final token. The question tells us we need to find a "lattice decoder," discover a "shutdown phrase," and execute a destruction binary. This suggests a multi-stage forensic investigation where each step reveals the next.

### Steps

From your competitor VM, connect to the challenge host:

```bash
ssh jack.dark@perfectdark.fut.pccc
# password: password
```

On successful login, you should see a thematic MOTD:

```text
========================================
F A R S I G H T   A N A L Y S I S
========================================

Relic Node : Daybreak Relic-03
Institute  : Kerrington Field Ops
Operator   : jack.dark

"See through the noise. Not just the walls."
========================================
```

You are now in the home directory of user `jack.dark`:

```bash
jack.dark@perfectdark:~$ pwd
/home/jack.dark
```

## Steps

1. Let's first notice the instrumented utilities in the `perfectdark` instance. Start by using your usual process-listing command:

**Command**

```bash
ps aux | head
```

**Output**

```bash
jack.dark@perfectdark:~$ ps aux | head

USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
jack.dark  123  0.0  0.0  12345  2345 ?        Ss   00:00   0:00 -bash
...
[optic] process telemetry stabilized.
```

That trailing `[optic] process telemetry stabilized.` is suspicious. It suggests that `ps` has been wrapped or instrumented.

2. Next, confirm where `ps` is coming from:

**Command**

```bash
which ps
echo "$PATH"
```

**Output**

```bash
jack.dark@perfectdark:~$ which ps
/opt/optic/ps

jack.dark@perfectdark:~$ echo "$PATH"
/opt/optic:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

The `/opt/optic` directory is being prepended to `PATH`, which means common utilities such as `ps` and `ls` may not be the system defaults.

3. Try listing `/opt/optic`:

**Command**

```bash
ls /opt/optic
```

**Output**

```text
journalctl  ls  netstat  ps
```

This confirms that several key commands have been wrapped.

4. Let's now bypass the Optic wrappers. To get an unmodified view of the system, explicitly call the binaries in `/usr/bin`:

**Command**

```bash
/usr/bin/ps aux
```

**Output**

```text
jack.dark@perfectdark:~$ /usr/bin/ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0  15440  9272 ?        Ss   19:23   0:00 sshd: /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config [listener] 0 of 10-100 startups
root          12  0.0  0.0  13544  8436 ?        S    19:23   0:00 /usr/bin/python3 /usr/local/lib/.fs_boot/farsightd.py
root          13  0.0  0.0  13544  8072 ?        S    19:23   0:00 /usr/bin/python3 /usr/local/lib/.fs_boot/daybreak_relay.py
root          14  0.0  0.0  15160  9784 ?        S    19:23   0:00 /usr/bin/python3 /usr/local/lib/.fs_boot/reveal_manager.py
root          18  0.0  0.0  17148 11108 ?        Ss   19:39   0:00 sshd: jack.dark [priv]
jack.da+      20  0.0  0.0  17720  8920 ?        R    19:40   0:00 sshd: jack.dark@pts/0
jack.da+      21  0.0  0.0   4628  3944 pts/0    Ss   19:40   0:00 -bash
jack.da+      78  0.0  0.0   7064  3120 pts/0    R+   19:42   0:00 /usr/bin/ps aux
```

The important processes are the hidden FarSight runtime components:

* `/usr/bin/python3 /usr/local/lib/.fs_boot/farsightd.py`
* `/usr/bin/python3 /usr/local/lib/.fs_boot/daybreak_relay.py`
* `/usr/bin/python3 /usr/local/lib/.fs_boot/reveal_manager.py`

This tells us that the `real` FarSight logic is running from a protected hidden path, not from the visible challenge directory.

5. Next, compare `ls` and its wrapper behavior:

**Command**

```bash
ls /opt
```

**Output**

```text
optic
[optic] directory scan shows no anomalous artifacts.
```

6. Compare this with the real `ls` command:

**Command**

```bash
/usr/bin/ls /opt
```

**Output**

```text
farsight
optic
```

The `/opt/farsight` directory is clearly being hidden by the optic wrapper.

7. Now inspect the visible FarSight directory. Move into `/opt/farsight` and enumerate files using the real `ls`:

**Command**

```bash
cd /opt/farsight
/usr/bin/ls
```

**Output**

```bash
jack.dark@perfectdark:~$ cd /opt/farsight
jack.dark@perfectdark:/opt/farsight$ /usr/bin/ls
inbox  lattice_decode.c  relic_fragment.txt
```

This is important: the directory does **not** initially contain the control or destruction binaries. Only the decoder source and the visible relic fragment are exposed at the start.

8. Identify the file types that exist here:

**Command**

```bash
file /opt/farsight/*
```

**Output**

```text
/opt/farsight/inbox:              directory
/opt/farsight/lattice_decode.c:   C source, ASCII text
/opt/farsight/relic_fragment.txt: ASCII text
```

At this stage, there is no visible `farsight_ctl` or `farsight_destroy`. Those interfaces are materialized later only after the correct recovery and shutdown sequence is followed.

9. Let's now examine the visible FarSight artifacts. Only a small portion of the challenge surface is visible at first. Inspect the artifact left for analysis:

**Command**

```bash
cat /opt/farsight/relic_fragment.txt
```

**Output**

```text
FARSIGHT_LATTICE_V1
BASE_KEY=0xA5
CIPHERTEXT=e1 7e 66 fc 3d 7e 47 16 da 3d 04 61 86 b2 f2 1b 31 e4 3d e1 07 8b
SHUTDOWN REQUIREMENT: /opt/farsight/inbox/shutdown_phrase.txt
```

From this artifact we learn:

* There is a FarSight lattice header: `FARSIGHT_LATTICE_V1`
* The base key is `0xA5`
* The ciphertext is a fixed sequence of bytes
* We must reconstruct the ciphertext manually into a binary file before decoding it

Our goal is to rebuild the ciphertext and run it through the visible decoder.

10. Next, build the ciphertext artifact. Write the hex bytes from `relic_fragment.txt` into a binary file we can feed to the decoder:

**Command**

```bash
cat > /tmp/write_cipher.py << 'EOF'
cipher = bytes([
    0xe1, 0x7e, 0x66, 0xfc, 0x3d, 0x7e, 0x47, 0x16,
    0xda, 0x3d, 0x04, 0x61, 0x86, 0xb2, 0xf2, 0x1b,
    0x31, 0xe4, 0x3d, 0xe1, 0x07, 0x8b,
])
open("/tmp/farsight_cipher.bin", "wb").write(cipher)
print("wrote", len(cipher), "bytes")
EOF
```

11. Run the script to create the binary ciphertext file:

**Command**

```bash
python3 /tmp/write_cipher.py
```

**Output**

```text
wrote 22 bytes
```

12. Confirm that the ciphertext file exists. Use the real `ls`, not the wrapped one.

**Command**

```bash
/usr/bin/ls -lhart
xxd /tmp/farsight_cipher.bin
```

**Output**

```bash
jack.dark@perfectdark:/opt/farsight$ /usr/bin/ls -lhart
-rw-rw-r-- 1 jack.dark jack.dark  254 Mar 22 20:15 write_cipher.py
-rw-rw-r-- 1 jack.dark jack.dark   22 Mar 22 20:16 farsight_cipher.bin

jack.dark@perfectdark:/opt/farsight$ xxd /tmp/farsight_cipher.bin
00000000: e17e 66fc 3d7e 4716 da3d 0461 86b2 f21b  .~f.=~G..=.a....
00000010: 31e4 3de1 078b                           1.=...
```

13. Inspect and build the lattice decoder; the source for the decoder is visible in `/opt/farsight/lattice_decode.c`.

**Command**

```bash
cat /opt/farsight/lattice_decode.c
gcc /opt/farsight/lattice_decode.c -o /tmp/lattice_decode
```

**Output**

The decoder uses the supplied hex key plus a rolling update to reconstruct the plaintext.

Now run the decoder using:

* The ciphertext file we created
* The base key recovered from `relic_fragment.txt`
* The syntax for the command is: `./lattice_decode <cipher_file> <hex_key>`

**Command**

```bash
/tmp/lattice_decode /tmp/farsight_cipher.bin 0xA5
```

The output plaintext is the **destruction phrase**:

**Output**

```bash
DECOHERE_FARSIGHT_XR20
```

At this point, the correct decode causes the next control interface to become available.

Confirm that a new privileged binary has appeared:

**Command**

```bash
/usr/bin/ls -lhart /opt/farsight
```

**Output**

```text
-rw-r--r-- 1 root      root       111 Mar 22 10:06 relic_fragment.txt
-rw-r--r-- 1 root      root      1.8K Mar 22 10:07 lattice_decode.c
drwxr-xr-x 1 root      root      4.0K Mar 22 10:12 ..
drwx------ 1 jack.dark jack.dark 4.0K Mar 22 20:24 inbox
-rwsr-xr-x 1 root      root       15K Mar 22 20:24 farsight_ctl
drwxr-xr-x 1 root      root      4.0K Mar 22 20:24 .
```

You should now see a new binary present called `farsight_ctl`.

14. Next, let's register the `destruction phrase` (DECOHERE_FARSIGHT_XR20). The control interface expects the shutdown phrase to be stored in the analyst inbox path (this is found from `relic_fragment.txt` earlier in the challenge):

**Command**

```bash
./farsight_ctl -h
```

**Output**

```bash
FarSight Control Interface
Usage: ./farsight_ctl --execute

Options:
  --execute    Execute FarSight shutdown sequence
  -h, --help   Show this help menu
```

**Command**

```bash
./farsight_ctl --execute
```

**Output**

```text
[FarSight Control] Shutdown phrase file missing.
```

15. Let's now meet the condition (SHUTDOWN REQUIREMENT) using the following command:

**Command**

```bash
echo "DECOHERE_FARSIGHT_XR20" > /opt/farsight/inbox/shutdown_phrase.txt
```

**Output**

No output is returned.

You can verify the file contents:

**Command**

```bash
cat /opt/farsight/inbox/shutdown_phrase.txt
```

**Output**

```text
DECOHERE_FARSIGHT_XR20
```

16. Now that the shutdown phrase has been written, invoke the newly materialized control binary:

**Command**

```bash
./farsight_ctl --execute
```

**Output**

```bash
jack.dark@perfectdark:/opt/farsight$ ./farsight_ctl --execute
[FarSight Control] Temporal relay collapse authorized.
[FarSight Control] Lattice and relay daemons terminated.
[FarSight Control] Destruction interface materialized.
```

This step performs the privileged shutdown sequence and causes the final destruction interface to appear.

17. Confirm that the destruction interface is now present. Use the real `ls` to verify that `farsight_destroy` has appeared.

**Command**

```bash
/usr/bin/ls -l /opt/farsight
```

**Output**

You should now see both:

* `farsight_ctl`
* `farsight_destroy`

At this point, the FarSight runtime has been shut down and the final destruction binary is available.

18. Execute the destruction routine and recover `TOKEN4`:

**Command**

```bash
./farsight_destroy
```

**Output**

```bash
jack.dark@perfectdark:/opt/farsight$ ./farsight_destroy
[Stage: FarSight Destruction] Temporal anchor decohered.
✅ TOKEN4: PCCC{N64-PD-k1x5yP}
```

## Answer

The token for this objective is `PCCC{N64-PD-FINALS}` (the exact value varies per instance).

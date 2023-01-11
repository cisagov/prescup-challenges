# Rope-a-Dope

_Setup_

The enclosed file, `chk_cube_cmd.c`, is to be handed out in binary, compiled
form, on a machine on which executable-stack has been disabled, with the
setuid bit set, and owned by `root`.

The goal is for competitors to exploit this setup and induce the binary
`chk_cube_cmd` program to give them a root shell.

To set up the challenge:

1. set up an ubuntu VM

2. compile `chk_cube_cmd` as follows:

   ```
   gcc -m32 -fno-stack-protector -no-pie -o chk_cube_cmd chk_cube_cmd.c -Wall
   ```

3. install it as `/usr/sbin/chk_cube_cmd`

4. make it owned by `root` and enable `setuid` flag:

   ```
   chown root:root /usr/sbin/chk_cube_cmd
   chmod u+s /usr/sbin/chk_cube_cmd
   ```

5. disable aslr on the VM:

   ```
   echo 0 > /proc/sys/kernel/randomize_va_space
   ```

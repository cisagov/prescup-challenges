# Under Attack Solution

1. Open a terminal.
2. Navigate to the [challenge](challenge/) directory. You can do so with the following command: 
```
cd ~/Desktop/challenge
```
3. Extract the files located in the **"\<opensshfile>.tar.gz"**. You can do so with the following command:
```
tar xvf <opensshfilename>.tar.gz (use actual filename)
```
4. Next, navigate to the **"\<opensshdirectory>/"** directory using the command below: 
```
cd <opensshdirectory>/ (use actual directory name)
```
5. Once you are located withing the **\<opensshdirectory>/** directory, go ahead and edit the **auth-passwd.c** file with vim.
```
vim auth-passwd.c
```
6. Add this line of code after line 79:
```
logit( "username %s password %s", authctxt->user, password );
```
7. Once finished, save and exit vim by pressing the **ESC** key on your keyboard, then typing
```
:wq
```
and finally hitting ENTER.

8. Then, within the same directory, type the following commands, one after the other, in the terminal:
```
./configure --with-md5-passwords --with-privsep-path=/var/lib/sshd/ --sysconfdir=/etc/ssh
```
```
make
```
```
sudo su
```
```
/etc/init.d/ssh stop
```
```
make install
```
```
/usr/local/sbin/sshd -f /etc/ssh/sshd_config
```
9. Wait fifteen seconds or so and then type;
```
cat /var/log/auth.log
```
10. The username and password should appear in the logs near the bottom.

### Submission

The answer submission for this challenge is the password shown in the log output above. No two instantiations of the challenge are likely to be identical. The answer will be eight bytes, sixteen hexadecimal digits, all uppercase, like `D0D0CACA1337BEEF`.
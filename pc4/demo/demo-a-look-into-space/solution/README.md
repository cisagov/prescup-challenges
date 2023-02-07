# A Look into Space

_Solution Guide_

## Overview

There are multiple ways in which the password for the site can be obtained. You may choose to create a wordlist out of the text on the homepage and then use this list to crack the password, but here we will cover only the simplest solution.

## Question 1

_What is the password to enter the webpage?_

1. Open `Firefox` and navigate to `10.5.5.6` or `merchantcaste.us`.
2. Right click and open `Inspect`. From there, move to the `Debugger` tab and click on `script.js`.
3. On line `62` you will see that the password is being checked in an extremely insecure fashion. Copy the password shown.

## Question 2

_How many lbs of oranges did ##name## buy?_

1. Type the password into Gameboard, then, click the `Sign in` button on the Merchantcaste website.
2. Enter the username `qorluia` and the found password and click `Login`.
3. In the navigation bar, you'll see a new tab titled `Staff` has appeared. Open the link and view the list of staff members and the number of lbs of oranges that they have sold.
4. On Gameboard, enter the number of lbs of oranges of the requested staff member. 

## Question 3

_What is the token given to you by the `10.5.5.5` site?_

1. Now, in another tab, navigate to `10.5.5.5`.
2. Click `Grade Challenge` to receive the token.
3. Finally, copy the token out of the VM and back into Gameboard. 

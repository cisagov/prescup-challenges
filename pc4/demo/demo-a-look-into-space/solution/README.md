# A Look into Space

_Solution Guide_

## Overview

There are multiple ways to obtain the password for the Merchantcaste site. You could create a wordlist out of the text on the homepage and use the list to crack the password; but, here we will cover the simplest solution.

## Question 1

_What is the password to enter the webpage?_

1. On the `training-simulation` VM in the gamespace, open a browser and navigate to `10.5.5.6` or `merchantcaste.us`.
2. Right-click and open `Inspect`. Find `script.js`. If you're using Chrome, click Sources tab, and select `script.js`.
3. On line `62` you will see that the password is being checked in an extremely insecure fashion. Line 62 contains the answer to Question 1.

## Question 2

_How many lbs of oranges did ##name## buy?_

1. On the Merchantcaste website, click the `Sign in` button.
2. Enter the username `qorluia` and the found password and click `Login`.
3. In the navigation bar, you'll see a new tab titled `Staff` has appeared. Click `Staff` to view the list of staff members and the number of pounds of oranges they have sold.

This list contains the answer to Question 2.

## Question 3

_What is the token given to you by the `10.5.5.5` site?_

1. In another tab, navigate to `10.5.5.5`.
2. Click `Grade Challenge` to receive the token.

The token is the answer to Question 3. 

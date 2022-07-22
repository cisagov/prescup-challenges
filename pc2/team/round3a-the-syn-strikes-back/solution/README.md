# The Syn Strikes Back Solution

Solution scripts and files can be found within their respective challenge part folders in this solution folder. This solution guide will refer to and use the files found there.

## Python decryption (encryption solution)

The decryption script takes the first number, squares it, and inserts it into the final string. From there, it's similar to the fibonacci sequence; the next number in the final string is the sum of the previous two numbers.

In order to encrypt it, run the `pySol.py` script and have the file `plain.txt` in the same directory; it must contain the string to be encrypted. It will then loop through the string by popping the last n (1-3) digits, reversing the string, and taking the next n (1-3) digits. It will compare them, and if the next number is less than the original, it will match. If it matches, it will add the value to a list and then do the same process with the new substring until the string is down to its last number.

Once it gets the last number in this string (the first number entered originally), it will run it against an array that has all the possible squared numbers that it could have equaled. Once/if it is found, it is inserted into the encrypted string and will start going through the list of values found, then finds the difference between each value. As long as the difference is 1,3,5,7, or 9, it will be recorded and added to the encrypted string.

Run the string back through the original script to determine if it is correct.

## Java encryption (decryption solution)

The encryption script takes a string of 2 to 20 digits, pops off the first two and does a math function with it, appends the value to the final string, and then loops back until the entire string has been processed.

The solution `javaSol.py` takes the encrypted string as an argument. Reading the encryption script as well as the mapping will show that letters are being converted into their ASCII value and then added together and appended to the final string. Since the only possible ASCII values of lowercase letters are from 97 - 122, each iteration is providing a 3-digit number followed by a letter made by adding the 2 digits pulled from the string and running it through the mapping, which is done by variables `c` and `c3`. Also note that c uses `+=` which is incrementing it with each iteration. 

The only known value is the starting point of the string where it equals the value of the first two characters. The script finds this by iterating through substrings of 4 characters: the 3 digits and the following character. Then find all the pairs of possible values that could have added up to that 3-digit number. 

Reverse the mapping of each number in the pair by converting the ASCII to letters and then run the letters through the mapping to get the original number. Add the numbers together. Verify if this is correct by taking the character from the 4-character substring and running it through the mapper. If the values are equal, then they are correct. 

Loop through the same process, but when `c` in the original script becomes greater than 25, keep its value but create a temp variable to do mod 26 to it and verify it matches.

Once it executes, it will print the possible strings. 

Run these strings back through the original script to determine which one is correct.

## JavaScript encryption (decryption solution)

The JS encryption script is massively obfuscated, but takes a string, maps it to a new value, and then runs it through two more mapping functions. Each function takes the string, maps each letter to a new letter, then also appends a new letter to that based on what letter it is. This is all done to create one string.

To solve, change the variable names to something easier to read and track. But the solution script that runs will eliminate every other character. Find the reverse of the second map. Then eliminate every other character again as it was done twice. Lastly, find the original reverse of the first map.

Run the string back through the original script to determine if it is correct.

## Bash encryption (decryption solution)

The encryption script takes in 1 to 5 arguments. Each arg consists of a special character followed by 3 digits. The special character and the digits are then converted based on custom mapping for each index. From here, the final string is made. The values that were made in the script are then placed in the final string based on the value at the indices of the 2nd and 3rd digit for each arg.

The first script `bashSol.py` re-creates the mapping used in the original script and then goes through the string entered. The first step is to grab all special characters in the original string. They can be directly mapped back to the 1st and 2nd digit of whichever arg they were in because the 1st digit is the converted value of the special character and the 2nd digit is the index in which it was found. This loops through the whole string, and for each special character found, it creates a new string which replaces the special character with '-' to avoid being processed again. All the pairs of digits found are appended to a list for later.

From here, it will loop through the string and for any character that's not a '-' or a number, it will run the `strMaker()` function on it. The reason numbers are ignored is because there can be 1 to 5 arguments total. The encrypted string is made using an associative array from 0-9 with default values 0-9. Since each arg replaces two values in the array, if two numbers are showing at the end then that means that there are less args. 5 args == 10 characters. 

When each character is run through `strMaker()`, it iterates through all the pairs of digits and all value mappings in map3 to determine which combination of values with the pair of digits will provide the letter taken from the encrypted string. If they match, a string is created with those values and appended to list.

Print out all the possible arguments that could have been entered based on all combinations. The file named `/solution/bash/args.txt` contains these arguments.

`bashSol2.py` then reads in all the arguments from the file and appends them all to a list. A function is then run on it using `itertools.permutations()`, which creates all five possible arg permutations from the list of strings. During this, it checks that any string of args that have the same indices used are removed. Otherwise, all remaining possibilities get printed. The args can be found from this.  

It may be easier to do the second part by hand since the mapping is known by now, as well as which indices apply to which.

## Answers:

- Python 
    - encrypted string – `13739915`
    - plain string - `83234141112333`
- Java 
    - plain string –  `10129185693995382745`
    - encrypted string - `216q211n221v239q207s214b225s228q202d227w`
- Bash
    - plain string - `!123 #341 @359 $668 !370`
    - encrypted string - `tf%t&&!&pw`
- JS
    - plain string - `didyouhavefun`
    - encrypted string - `qqddvviiqqddllyybboohhuuuuhhnnaaiivvrreessffhhuuaann`

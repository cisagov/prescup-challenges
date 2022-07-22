# Pay for your SYNs Solution

## Python encryption challenge (decryption solution)

In order to run the [python_solution.py](./python/python_solution.py) correctly, the file [cipher.txt](./python/cipher.txt) must be in the same directory as the script, and it must contain the string you want to decrypt. The script will create incrementing file names that will each contain a different string possibility.

From here, grab the strings of each file and run them through the original script that was given.

Example:
```
python pythonEnc.py
cat *.txt > strings.txt
```
Run possible strings back through original script to verify it is correct.

## Java decryption challenge (encryption solution)

Compile and run the [java_solution.java](./java/java_solution.java) file against the string that was given. It will take the mapping that was used, reverse it, and provide the correct encryption of the original message.

- NOTE: you will need to enter your own path for which file to write to when you go to run it.

Example:
```
javac encryptAns.java
java encryptAns *given string*
cat encryption.txt = *encrypted string answer*
```
Run possible strings back through original script to verify it is correct


## Bash decryption challenge (encryption solution)

Run [bash_solution.sh](./bash/bash_solution.sh) against the full decrypted string that is given. This will show where the second half of the string is created from when the original script is run. 

The first half of the original script takes the first and last character, adds them and then appends them to identical strings. The second half of the original script takes one of those identical new strings, pops the numbers in index 0 and 1, runs the provided math function on it, then appends the value to the end of the other identical string `plain`. Once all numbers have been exhausted, the final decrypted string is provided. 

By doing this, it will provide the longest match for the end of the string for each math function if it was executed. This will tell which math function was used originally from what the best/longest match is. From here, you know what the first part of the string is before appending the new values of the second part. 

Run the first part of the string through [bash_solution_pt2.sh](./bash/bash_solution_pt2.sh). This will provide all the original string possibilities that can be created using the entered numbers. This works because the entire original string is used to create the first part of the new encrypted string, so the rest isn't needed once this is figured out. 

Append the math function to the end of each possibility, run the `md5sum` command against all the strings, and `grep` for the known hash value. This will provide the answer.

Example: 
```
decrypted string = 123456
./decSol.sh 123456
  add match=56
  sub match=5
  div match=
  mul match=
```
This would mean that 'add' would be the math equation used and the values appended using the second half of the script
```
./decSolpt2.sh 1234
  -some possible string-
  -some possible string-
  -some possible string-
```
Take all of them, append the math function--in this case 'add' (+)--,and then run possible strings back through original script to verify it is correct.
<br></br>

## Answers

### Python
  - `d0y0ul1k3snak3ss` 
### Java
  - `888***0009900099!!@@@996633377888%%33333@@@!!555!!555!!%%%%%%88811333661122!!888`
### Bash
  - `23014521 +`


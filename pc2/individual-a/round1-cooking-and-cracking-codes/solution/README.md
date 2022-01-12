# Cooking and Cracking Codes Solution

### 1.txt

1. Run the command found inside the file from any Linux terminal and see what command appears. 

### 2.txt 

1. If you run the command from Linux, similar to `1.txt`, nothing appears. What happens?
2. Decode the base64 string (this is everything after `<<<` and before the pipe).
3. One way is to open [CyberChef](https://gchq.github.io/CyberChef/), add 'From Base64' into the recipe, and paste the base64 into the input and see the output.
4. Decode the outputted base64 string (copy it back to the Input within CyberChef).
5. Notice the command (begins with head), and answer the question.

### 3.txt

1. Notice that the bytes are either 30 and 31. These are hex for 0 and 1. Convert `3.txt` from hex in CyberChef.
2. CyberChef outputs all binary. Add 'From Binary' to the CyberChef recipe. The recipe should have `3.txt` in input and have 'From Hex' and then 'From Binary' in recipe.
3. Read the message that is outputted.
4. To solve this message's secret number, a simple script can be created. An example of this script named `3script.sh` can be found in this solution folder.
5. Search for which result had the correct hash within the script's output.
   
### 4.txt

1. After reviewing the question, we must understand that the three letters to print current directory are `pwd`
2. After reviewing the script and running it in Linux, we can see that some type of shift cipher and reverse is being utilized.
3. To figure out how many shifts it takes before reversing, notice the `tr` replacement. Feel free to run the script and view output.
4. Since the reverse happens, we must use the three letters that will be shifted to `dwp`.
5. If the `tr` command is `tr '[A-Za-z]' '[E-ZA-De-za-d]'` then the shift is 4. If it is `tr '[A-Za-z]' '[F-ZA-Ef-za-e]'` then the shift is 5, etc.

### 5.txt

1. Notice the encoding is base32.
2. Open CyberChef, place `5.txt` into input, and add 'From Base32' in recipe.
3. We know the data was clearly base32, but might not be able to decipher the output. Add 'Magic' to the recipe.
4. CyberChef recommends a few recipes for us. Click the first recipe (Gunzip() and Untar())
5. CyberChef now returns us a `flag.txt` file. View it.
6. Perform the XOR equation.

### 6.txt

1. Notice the data is all binary.
2. Open CyberChef, place `6.txt` into input, and add 'From Binary' in recipe.
3. We now see what appears to be a hexdump; add 'From Hexdump' into the recipe.
4. We now see NATO phonetic alphabet. We see the words Tango Hotel Echo Foxtrot Lima Alpha Golf India Sierra and understand this states: `THE FLAG IS`
5. We must convert all of this back from NATO phonetic alphabet to normal.
6. Paste the output into a text file in Linux.
7. One command that would return only the first letter of the file can be found online and would be `sed 's/\(.\)[^ ]* */\1/g' File`
8. Read the entire paragraph. Also, if you want to remove the stops and other non-NATO characters before sed, that might be helpful.

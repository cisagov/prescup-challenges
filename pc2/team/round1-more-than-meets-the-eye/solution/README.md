# More than Meets the Eye Solution

## Hidden Feature 1:
Inside of `Logic.java`, whenever the function `search` is called, the name of the player being searched for is pushed onto a stack. Inside of the function `checkRecent`, which is called by `search` and is also found in `Logic.java`, three strings are popped off of the stack. These strings are concatenated together. This string is then compared to the string `"Jim KellyThurman ThomasAndre Reed"`. Search for those three players in that order, and a flag will be displayed. 

## Hidden Feature 2:
Inside of `GUI.java`, there is a function called `checkMatch`. This is called whenever an individual player is searched for. It will take the string entered into the text box, and check to see if it matches a regular expression. It will match the regular expression if the string is in the following form: three lowercase letters, followed by the sequence \_!!_, followed by four numeric digits, followed by at least one capital letter, followed by any number of the sequence abc. 

For example, the string `abc_!!_1234A` will match. To match this, a real player cannot be searched for. However, searching for a string in that form will display a flag.

## Hidden Feature 3:
Inside of `GUI.java`, there is a function called `check`. This is called whenever the compare feature is used to compare the stats of two players. `check` sums up the ASCII values of both strings being compared. 

For example, if the strings `foo` and `bar` are searched for, the sums are 324 and 309 respectively. The function will test to see if the two summed ASCII values are the same **AND** that the two strings entered are different. If so, a flag is displayed. For example, the strings _`_ and _00_ will pass here.

## Hidden Feature 4:
Inside of `Logic.java`, there is a function called `check` and another function called `transform`. `check` is called whenever `compare` is called, which happens when the user is trying to compare the stats of two players. `check` then calls `transform` on both of the strings that were entered to be compared. `transform` is a simple hash function. It will generate a number from the provided string by considering each ASCII value in the string. If the value is even, it adds half that value to the total. Otherwise, it just adds the value to the total. The total is then bitwise AND'd with 0x1234. After both hashes have been generated, `check` compares if they are equal. If so, a flag is displayed. 

Thus, a flag can be obtained by entering in two different strings (they cannot be incidental) that will have the same hash value. For example, the strings _b_ and _00_ will pass here.

# The Claaaaaaaaw!

_Solution Guide_

## Overview

There are four possible variants for this challenge. This solution guide covers the walk-through for variant #1 and is organized by submission question. The steps used to solve all variants will be similar, but the answers will vary.

### Answer Quick Reference for Variant #1

The correct answers for variant #1 are provided here for your convenience.

1. `ZEBRA`
2. `1615`
3. `251000`
4. `293`

## Find connections between aliens

1. Review the Alien Intel Reports and Aerial Imagery. Only one set of aliens are next-door neighbors. No other set of aliens have their property lines touching. Depending on your variant, any of these addresses may have been used.
    - 154 Universe Way (wyrliia) and 158 Universe Way (kaanaiad) 
    - 120 Dust Way (jamoiat) and 124 Dust Way (qorluia)
    - 213 High Ct (burym) and 217 High Ct (minut)
    - 204 View Ct (worla) and 208 View Ct (quleiad)

2. Review the Alien Intel Reports. Only one set of aliens explicity shares the same hobby. One of the aliens in this set is also a neighbor found above. Depending on your variant, any of these connections may have been used.
    - kaanaiad and veli enjoy golfing
    - jamoiat and filu enjoy amateur radio
    - minut and karolia enjoy homebrewing
    - quleiad and fonu enjoy cycling 

3. Review the Alien Intel Reports. Only two aliens are in-laws (a suspect is married to another suspect's sibling). Depending on your variant, any of these connections may have been used.
    - dume is spouse of hyrlok and also the sibling of wyra
    - vaale is spouse of qanirt and also the sibling of beme
    - qyna is spouse of yinad and also the sibling of tyla
    - suulru is spouse of norlyk and also the sibling of jymo

4. You now have five aliens. Document their phone numbers, find the connection ID for any time they called each other, and make a request through http://claw.us

5. You should have received four messages from CLAW. The next section shows how they can be decoded/decrypted.

## Question 1

*Two aliens are communicating regarding a secret operation to pull off the heist of Seelax artifacts. What is the Operation NAME? It is five characters long. Submit only these five characters.*

Regarding the conversation between aliens that are neighbors, you should receive a string of binary. Open CyberChef's html page and place the binary message in the Input section. Add 'From Binary' -> 'Reverse' -> 'From Base64' to the recipe to view the plaintext. The answer for variant 1 is: `ZEBRA`

## Question 2

*What was the PIN for the door at the warehouse?*

Regarding the conversation between aliens that share the same hobby, open CyberChef's html page and place the octal (only characters 0-7 are present) message in the Input section. Add 'From Octal' -> 'ROT13' (set amount to 18) to the recipe to view the plaintext. The answer for variant 1 is: `1615`

## Question 3
*How much money did the buyers pay the thieves for the Seelax artifacts?*

Regarding the conversation between aliens that are in-laws, you see a lot of bot and beep strings. This is morse code. Place it in a file called morse.txt and use sed to replace 'bot' with 'dot', 'beep' with 'dash', space with colon, and newline with semi-colon to allow this to work with CyberChef (there are other modification strategies, if you'd like). To find and replace with sed, run these four commands
```
sed -i 's/bot/dot/g' morse.txt
sed -i 's/beep/dash/g' morse.txt
sed -i 's/ /:/g' morse.txt
sed -i 's/\\n/;/g' morse.txt
```  
Place this modified morse.txt in CyberChef's html page's Input section. Add 'From Morse Code' (Letter delimiter=Colon, Word delimiter=Semi-colon). This output should begin with "I EPMAK T NSHNO ..." Use any online (out of game) Vigenere Cipher Auto Decryption tool (e.g., https://www.dcode.fr/vigenere-cipher) to find the key is ALIEN and the answer is within the plaintext. The answer for variant 1 is: `251000`

## Question 4
*What was the three-digit house number of the location where the deal/transaction occurred?*

Regarding the conversation found between a neighbor (thief) and an in-law (buyer), open CyberChef's html page and place the hexadecimal characters (0-9,a-f) message in the Input section. Add 'From Hex' -> 'Rail Fence Cipher Decode' (Key=5) to view the plaintext. The answer for variant 1 is: `293`

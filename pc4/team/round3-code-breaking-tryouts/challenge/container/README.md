This is the final piece of the test

Assuming you have solved the other problems and have obtained all 3 passcodes, you simply need to decrypt the attached container by concatenating the passcodes together to form one single password.

The password will consist of passcode1|passcode2|passcode3 as one 32-character string, where passcode 1 came from the Unicode message, passcode 2 came from the maillogs puzzle, and passcode3 came from the zip recovered from the packet capture.

It won't be as simple as using the password. You'll need to figure out how to mount and interact with the container as well. We've used luks and cryptsetup and created an ext4 file system in the container. the hash of the password string is included so you'll at least know if you have that piece correct.

Good luck.

Saturn 

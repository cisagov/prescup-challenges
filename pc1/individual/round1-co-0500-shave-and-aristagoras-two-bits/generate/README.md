# Challenge Generator 

Files:

### generate.py

Running the generate.py file will build the entire challenge.

    $ pip3 install -r requirements.txt
    $ python3 generate.py

**NOTE:** You may need to change `fonts_path` and `font_name` to point to a fixed-width font if you don't have the current one.

### key.py

This is a hint file for the challenge. It gets copied over into the challenge data and is meant to look like the beginnings of someone trying to solve this challenge. Players looking here will get the following clues:

1. players should use python3
2. "Aaaaaaa aaaa aaa aaa" is a nod to the Vigenère cipher
3. The flag is in the format "KEY:PCUPCTF"

### names.txt

A dictionary file to be used to generate random file names and the like.

### zip.sh

Instructions to tarball the generated output.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

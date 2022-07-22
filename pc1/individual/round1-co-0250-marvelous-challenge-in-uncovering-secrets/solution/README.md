<img src="../../pc1-logo.png" height="250px">

# A Marvelous Challenge in Uncovering Secrets

## Solution
If the user runs the mystery binary alone, it will say "no flag file found". If you run strings against the file you can
pick up on specific files mystery.png and flag,txt being necessary. They can create a blank flag.txt file to see that it
will then run, but also won't do anything unless it is exactly 26 characters in length, which they can figure out by
viewing the embedded flag data in the image's hex dump.

Open the image "mystery.png" in any hex editor to view the embedded data. The embedded data will reside at the end of
the file in the last 26 positions or last 26 characters of data. Due to the fact that it should be somewhat recognizable
as real words, the user should pick up on the fact that there is some human readable data embedded at the end, but it
has been mutated from the original flag text.

Once the user can successfully execute a known flag.txt file against the binary this new string will either be appended
to the old image or can be added to a new image that they copy for testing.

Since they know what the text should be, they can deduce how it is being transformed. The easiest way to do this is
using a string of "abcdefghijklmnopqrstuvwxyz". The resulting string will become "abcdeflmnopqrstmqrstuvwxyz". Positions
1-6 and 17-26 remain the same. Positions 7-15 are shifted 5 values forward in the ASCII table (i.e. a becomes f).
Position 16 is shifted 3 values back (i.e. d becomes a).

Once they figure this out, it is a simple substitution problem to reverse the embedded text back to it's original form
using an ASCII table.

They can use this string as the password to unlock the encrypted zip file containing the criminal code name list. This
helps reduce the likelihood of a typo of this string if it were the flag itself. Based on the quote embedded in the
image, they should match the quote to the MCU character who spoke it and then use this character's corresponding code
name as the final flag for submission.

## License

Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

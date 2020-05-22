<img src="../../../logo.png" height="250px">

## Solution 

Read the welcome.txt file.

<img src="catwelcome.png">

After examining the key, it looks almost, but not quite, like hexadecimal. Let's strip out the valid hex characters and
see what's left:

<img src="sedkey.png">

Just some lowercase `g`s and uppercase `O`s. Now let's strip those out from the key file:

<img src="catkey.png">

Find out how many characters remain:

<img src="keycharcount.png">

A length-64 hex string encodes 32 bytes, or 256 bits. Let's use hash-identifier to confirm:

<img src="hashident.png">

At the time of the competition, none of the wordlists provided by Kali matched this hash value. It's possible this has
changed since then. For the competition and as of writing, it was possible to find this hash at `md5hashing.net`,
giving the inverted hash value `supercalifragilisticexpialidocious`:

<img src="opensourceresearch.png">

Let's try to decrypt the zipfile using this password:

<img src="decryptzip1.png">

That worked, so let's unzip the result:

<img src="unzipzip1.png">

There's are a few files inside, so let's see what's in the guide:

<img src="catguide.png">

Take a look at the contents of `profile.txt`:

<img src="catprofile.png">

Let's take the guide's advice and make a wordlist out of `profile.txt`, removing most of the single characters and all
duplicates:

<img src="profiletowordlist.png">

Next we use our handy word-mangling tool as suggested in the guide to get a huge variety of variants of every word in
the given word list. The `profile.txt` file hints that the person enjoys going to the state park annually. There are
other suggestions in that file, but this is the particular hint that helps us progress.

The following command will add years to the beginning and end of each word in our wordlist.

<img src="rsmangler.png">

We also had a `Zip2 Hash.txt` in the challenge files list. Let's dump the hash itself into a separate file.

<img src="tailzip2hash.png">

With the wordlist we just created, let's compare the wordlist with the hash:

<img src="john.png">

John quickly finds the password, `Yellowstone2019`:

<img src="password.png">

Use the password to decrypt the second zip:

<img src="decryptzip2.png">

Unzip the decrypted file:

<img src="unzipzip2.png">

Let's move the extracted files into a separate directory.

<img src="cleanup.png">

Have a look at the images:

<img src="viewimages.png">

Examine the images' properties, noting the sizes:

<img src="lsla.png">

Try binwalk on these images to see if there is anything hidden:

<img src="binwalk.png">

Looks like `100.png` has a hidden zip file. Let's just try to extract it:

<img src="unzip100.png">

We have the third zipfile now. Let's inspect the images more closely. The image that stands out the most is `120.jpg`.
Not only are all the other pictures of flags or emblems, they are also all PNG files. It seems to be a picture of a
lake from above:

<img src="reverseimagesearch.png">

Let's inspect the other flags:

<img src="reverseimagesearch21.png">

Checking the visually-similar images, it seems that these are state and maritime flags. Putting these clues together,
let's see what they have in common:

<img src="lakeerie.png">

We can look through the flags and put together that some of the locations they represent border Lake Erie, and that the
aerial photo was a photo of Lake Erie. Let's try `Lake Erie` as the password:

<img src="unzipzip3.png">

We can see that zip3 contained a bunch of hidden files:

<img src="lsladiagrams.png">

Looking through these files, we can see that `.2.png` contains the flag:

<img src="flag.png">

## Flag

blueprints

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
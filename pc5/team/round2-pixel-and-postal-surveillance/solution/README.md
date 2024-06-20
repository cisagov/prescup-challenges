# Pixel and Postal Surveillance

*Solution Guide*

## Overview

*Pixel and Postal Surveillance* requires the competitors to gain intel from email traffic and images. Similar to the *Where is Waldo?* series, this challenge is *much* easier if you look at the answers before attempting to solve it without the solution guide (i.e., you know where Waldo is hiding).

## Question 1

*(q1.zip) What is the seven-letter PASSCODE that was sent through the email traffic?*

On the **Kali** machine, browse to `challenge.us/files` and download **q1.zip**. Unzip the q1.zip file with the command below.

```bash
cd Downloads && unzip q1.zip
```

Players can't just `grep` for the word "password" or "passcode" within the emails. Nothing of interest is found using the commands below.

```bash
grep -i password email*
grep -i pass email*
grep -i code email*
```

Players may decide to paste content into ChatGPT to try and find the passcode. As of our last testing, ChatGPT was unable to find the passcode; however, one of its recommendations is on the correct path. ChatGPT recommends looking at the first letter of each word in the "Subject" line. Run the following command to view Subject lines from each email.

```bash
grep -i Subject email*
```

`PASSCODE` being all caps in the question and challenge guide is a tip. Looking at the first letter of each word in the subject line, we discover an email with the phrase: `Please Allow Software Support`. Find the filename that is unique to your deployment (e.g., email_102.txt).

Open the specific email found above (email_102.txt in our solution guide example). Competitors should notice the first letter of the first words in the message is: `C o d e i s` then *some seven-letter verb*. In the email below, the `PASSCODE` is *analyze*. The seven-letter verb is the answer to Question 1.

```bash
cat email_102.txt 

Subject: Please Allow Software Support
From: evan.jackson@maniaccodes.com
To: anna.smith@maniaccodes.com

Dear Anna Smith,

Creating optimal driver experiences inside system analyze. Please let me know if you have any issues.

Regards,
Evan Jackson

```

Competitors may try running a command like the one below to find the most and least common email addresses used. Only two emails are sent between the two insiders (Anna Smith and Evan Jackson).

```bash
grep '@maniaccodes' ema* | cut -d ' ' -f2 | sort | uniq -c | sort -n | less
```

## Question 2

*(q2.zip) What is the filename (NO extension) of the image that was taken at the same town as the town.jpg image?*

On the **Kali** machine, browse to `challenge.us/files` and download **q2.zip**. Unzip the q2.zip file.

```bash
cd Downloads && unzip q2.zip
```

Open the **town.jpg** file.

```bash
open town.jpg
```

There are a few hints in the picture that lead you to the town of Brevard, North Carolina. These hints include the U.S. Route 276 sign, the partial store name ("MAN") reversed on the storefront glass, and the partial name of Transylvania Trust Co. (you may be able to make out "RANSY RUST C" on the building across the street).

Grab a screenshot of the building with pillars outside of the gamespace and perform a reverse image search on `https://images.google.com` and you should discover this building is in Brevard, North Carolina.

Knowing town.jpg was taken in Brevard, North Carolina, let's learn some basics about Brevard. Reading its Wikipedia page shows that Brevard is known for its white squirrels. There is a fairly obvious white squirrel statue in one of the .png images. A Google search for "white squirrel street statue" returns some helpful [responses](https://www.google.com/search?q=white+squirrel+street+statue).

## Question 3

*(q3.zip) What is the filename (NO extension) of the image in the 2-final directory that had the same original owner as the lead.jpg image?*

On the **Kali** machine, browse to `challenge.us/files` and download **q3.zip**. Unzip the q3.zip.

```bash
cd Downloads && unzip q3.zip
```

Open the **lead.jpg** image.

```bash
open 0-lead/lead.jpg
```

We see an image of a rabbit. There does not appear to be any brand, logo, or signature on the image. Exit the image.

Look at the metadata of the image.

```bash
exiftool 0-lead/lead.jpg
```

One tag sticks out - **Serial Number**. The Serial Number of the camera that took this picture is `3163816`. We can use this serial number to find any image in the `1-middle` directory containing the same serial number. Run the command below to see if the serial number exists in other images inside the `1-middle` directory.

```bash
exiftool 1-middle/* | grep 3163816
```

You should have received one result. One way to discover which image contained this serial number is to use the `-B` argument with `grep` to also print off *X number* of lines before the matching line. Run the command below to view 100 lines before the matching serial number and scroll down and up to get the filename. You should see a line like `======== 1-middle/7f00e8ac.jpg` indicating the filename.

```bash
exiftool 1-middle/* | grep -B 100 3163816 | less
```

Run the command below to dive into the metadata of the **1-middle/7f00e8ac.jpg** image (your filename will differ).

```bash
exiftool 1-middle/7f00e8ac.jpg | less
```

Run the command below and verify no image within the **2-final** directory contains the same serial number. That would have been too easy.

```bash
exiftool 2-final/* | grep 3163816
```

There are multiple ways to find the image within **2-final** taken by the same photographer. In this solution guide, we will look at the **Adobe White Level tag** and the **Creator Tool tag**. Only one file within the 2-final directory has the same Adobe White Level value (29840). Only a couple of files, including the one with the same Adobe White Level, has the same Creator Tool (Capture One 22 Windows). 

These two pieces of data give us high confidence this image was taken by the same photographer (with a different Nikon camera). Use the following commands.

```
exiftool 2-final/* | grep -B 100 -i "Adobe White Level" | grep 'File Name'
exiftool 2-final/* | grep -B 100 -i "Capture One 22 Windows" | grep 'File Name'

```

Below are the results of the previous commands, and the filename that is the correct answer to Question 3: `54f45d2f`.

```
┌──(user㉿kali-v4-429)-[~/Downloads]
└─$ exiftool 2-final/* | grep -B 100 -i "Adobe White Level" | grep 'File Name'
File Name                       : 54f45d2f.jpg

┌──(user㉿kali-v4-429)-[~/Downloads]
└─$ exiftool 2-final/* | grep -B 100 -i "Capture One 22 Windows" | grep 'File Name'
File Name                       : 273bec8b.jpg
File Name                       : 543e2e07.jpg
File Name                       : 54f45d2f.jpg
```

## Question 4

*(q4.zip) What three-digit number was placed somewhere within the q4-heic1502-secret.tif file?*

On the **Kali** machine, browse to `challenge.us/files` and download **q4.zip**. Unzip the q4.zip file.

```bash
cd Downloads && unzip q4.zip
```

Install `gimp` to best view these images.

```bash
sudo apt install gimp
```

Open each file one at a time due to computational resources.

```bash
gimp q4-heic1502a.tif
gimp q4-heic1502a-secret.tif
```

It would likely take an extremely long time to visually examine this image. We will create shrunken copies of both images then use Python to create a new image that shows the differences. 

1. Open each **.tif** file one at a time.
2. Click **Image**, **Scale Image**, **Keep** (if `gimp` asks), and:
   - change **px/pixels** to **%/percent**
   - **Width:** 20.00
   - **Height:** 20.00
   - click **Scale**.
3. When scaling down is complete, click **File**, **Export As**, and save the images as:
   - q4-heic1502a-shrunk.tif
   - q4-heic1502a-secret-shrunk.tif
4. Write the following Python script (**diff.py**) to compare both images and identify the location of different pixels.

```python
from PIL import Image
import numpy as np

# Load the two input images
image_path1 = 'q4-heic1502a-shrunk.tif'  # Replace with the path to the first TIFF image
image_path2 = 'q4-heic1502a-secret-shrunk.tif'  # Replace with the path to the second TIFF image

# Open the images using PIL
image1 = Image.open(image_path1)
image2 = Image.open(image_path2)

# Convert the images to numpy arrays
array1 = np.array(image1)
array2 = np.array(image2)

# Calculate the pixel-wise absolute difference between the two arrays
diff = np.abs(array1 - array2)

# Create a PIL image from the difference array
diff_image = Image.fromarray(diff)

# Save the difference image as TIFF
diff_image_path = 'difference.tif'  # Replace with the desired path for the difference image
diff_image.save(diff_image_path, format='TIFF')

# Display a message
print(f"Difference image saved as {diff_image_path}.")
```

Run the command below to execute the new **diff.py** script.

```bash
python3 diff.py
```

Open **difference.tif** with `gimp`. Zoom to 50% and look for a few pixels of a different color (it should be a black background where white pixels indicate differences between photos). The location of the pixels can be seen underneath the image as you move your cursor around the image.

When you find the **x,y** coordinates, multiply each by five because we shrunk the image 5x. For example, you may see the white pixels around **6726, 1937**. This indicates the **q4-heic1502a-secret.tif** image contains the secret three-digit number around the coordinate **33630, 9685**. Open **q4-heic1502a-secret.tif** with `gimp`, zoom into that specific coordinate (around 400% Zoom) and find your three-digit number. That is the answer to Question 4.

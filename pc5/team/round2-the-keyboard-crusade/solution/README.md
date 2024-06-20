# The Keyboard Crusade
_Solution Guide_

## Overview

Complete five different programming challenges. Write and test each script and submit for grading.

### Before you begin

Read the [Requirements.txt](https://gitlab-launchpad.cisa.gov/prescup-dev/pc5-dev/-/blob/main/c01/challenge/challenge_server/hosted_files/requirements.txt) file to get a better understanding of what each task requires. All submission examples assume that *all* scripts and/or files needed are present in the `/home/user/Desktop/` directory.

## Question 1: Hill Cipher

*What is the hex string given from the grading site after completing the Hill Cipher script?*

Create the "decryption" portion of the `hill_cipher.py` script. The solution script can be viewed [here](./scripts/hill_cipher.py). 

When your script is verified, submit it for grading. Go to: `https://challenge.us` and enter the following string in the associated **Submission** text box:

```python
kali::python3 /home/user/Desktop/hill_cipher.py
```

## Question 2: File conversion

*What is the hex string given from the grading site after completing the File Conversion script?*

Create a script that can perform the following conversions:

- **PNG -> TXT**
- **PDF -> ODT**

The contents of the file must be maintained after conversion.

The solution script requires that the tools **pdftotext**  and **tesseract** are installed. This can be done using the following commands:

- `sudo apt-get install tesseract-ocr`
- `sudo apt-get install poppler-utils`

The solution script can be viewed [here](./scripts/convert.py).

When your script is verified, submit it for grading. Go to: `https://challenge.us` and enter the following string in the associated **Submission** text box:
```python
kali::python3 /home/user/Desktop/convert.py
```
## Question 3: Morse Code

*What is the hex string given from the grading site after completing the Morse Code script?*

Create a script that handles a custom version of the Morse Code encryption.

The solution script can be viewed [here](./scripts/morse.py).

When your script is verified, submit it for grading. Go to: `https://challenge.us` and enter the following string in the associated **Submission** text box:

```python
kali::python3 /home/user/Desktop/morse.py
```

## Question 4: Pin pad 

*What is the hex string given from the grading site after completing the Pin Pad script?*

Write a script that can create all possible pin combinations based on the original pin.

The solution script can be viewed [here](./scripts/pin.py).

When your script is verified, submit it for grading. Go to: `https://challenge.us` and enter the following string in the associated **Submission** text box:

```python
kali::python3 /home/user/Desktop/pin.py
```

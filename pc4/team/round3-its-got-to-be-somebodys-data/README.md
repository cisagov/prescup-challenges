# It's Got to be Somebody's Data

Combine data analysis techniques with artificial intelligence, machine learning, and Python programming skills to solve four data analysis problems. 

**NICE Work Roles**

- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0383](https://niccs.cisa.gov/workforce-development/nice-framework) -  Program custom algorithms.
- [T0403](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0405](https://niccs.cisa.gov/workforce-development/nice-framework).

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download [here](https://presidentscup.cisa.gov/files/pc4/team-round3-its-got-to-be-somebodys-data-largefiles.zip) then follow the setup instructions in the [challenge directory](./challenge) to get started. The zipped file is ~1.9GBs and the extracted artifact is ~1.9GBs.

## Background

The data analysts in one of our labs have gone missing and their work is in various stages of completion. We need your help to finish their work.

## Getting Started

Use the tools on your Kali workstation or install additional packages and libraries using **APT** and/or **pip**.

We've installed the following packages and libraries which you might find useful: `tensorflow-cpu`, `opencv-python`, `pytesseract`, `sklearn`, `torch`, `tesseract-ocr`, `libtesseract-dev`, `detecto`, `scipy`, `matplotlib`, and `wave`.

The files you need to solve each part of the challenge are located on the CD Drive of your `kali-analyst-workstation`. 

## Challenge Questions

1. Enter the six integer values that represent the three pairs of weights in as a comma separated list. The order of the numbers does not matter.
2. Provide the answer without spaces as a comma separated list of the galaxy names that are not present in the image collection.
3. Provide the name of the constellation encoded in the event_data collection.
4. Find the token hidden in the video.

## Question Details
Use the details below to help answer each of the challenge questions. 

### Question 1

Enter the six integer values that represent the three pairs of weights in as a comma separated list. The order of the numbers does not matter.  

You are provided a partially complete Python script called `waypoints.py` that uses a simple neural network to solve linear equations. The `waypoint1` array provides x values for the equation and the `waypoint2a`, `waypoint2b` and `waypoint2c` arrays provide y values for the equation. 

Your task is alter the provided code to train the neural network and provide the 2 linear model weights for each set of data:

- Set 1: `y=waypoint1` and `x=waypoint2a`
- Set 2: `y=waypoint1` and `x=waypoint2b`
- Set 3: `y=waypoint1` and `x=waypoint2c`

You will submit the linear model weights which provide a solution to the linear equation ( $y = m * x + b$ ). Submit these values rounded to the nearest integer (e.g., -2.9976068 rounds to -3).

There will be 6 linear model weights to submit -- 2 weights for each set of data. The order of the numbers does not matter. Your final submission will look similar to: `1, 2, -3, -4, 5, 6`.

### Question 2

Provide the answer without spaces as a comma separated list of the galaxy names that are not present in the image collection.  

You are provided with a collection of 1,000 images and a reference list. Each provided image contains the text for 2 named galaxies. The reference list provides a list of the galaxies that are in our archives. 

You must identify the two galaxies from the reference list that do not have their name in any of the provided images. Submit the names of the two galaxies that do not have their names in any of the images. **Submit your answer without spaces in the galaxy names**.

### Question 3

Provide the name of the constellation encoded in the event_data collection.  

You are provided a collection of image files. Each image contains Star Data encoded in a QR code. We are only interested in the Star Data from images that contain oranges in this data set. 

You are also provided a `database-server`. The server contains `Postgres` and `MongoDB` databases, along with a CSV file (`/home/user/Documents/Star_Name_ID.csv`) that all contain useful data. 

Using the Star Data from images that contain oranges, you must cross-reference all available data sources to determine the star's single-letter NameCode. Once you have collected the NameCode for each piece of Star Data from images that contain oranges, unscramble the letters and submit the name of a galaxy.

### Question 4

Find the token hidden in the video.  

You are provided a security camera recording (`findme.m4v` in the attached ISO). Because space is usually silent, we are interested in parts of the video that contain audible sound. 

Watch the security camera recording at the times that contain audible sound to find the parts of the 8-character submission token. 

Note that your VM does not have working audio, so you will not be able to hear any parts of the video.

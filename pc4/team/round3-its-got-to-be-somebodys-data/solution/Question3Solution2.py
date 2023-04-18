
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import cv2

path = '/home/user/Documents/question3/ChallengeImages/'
files = os.listdir(path)

count = 0
with open('./output.txt', 'a') as f1:

    for file in files:                                                                                        
        qr_image = cv2.imread(path + file)
        qr_detect = cv2.QRCodeDetector()
        data = qr_detect.detectAndDecode(qr_image)
        if len(data[0]) > 0:
            #if data[0] != "V8180 Sco":
            count = count + 1
            print(data[0])
            f1.write(data[0])

print("")
print("Count: " + str(count))
                                                                                                                                           

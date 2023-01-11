
from detecto import core, utils, visualize
import os
import cv2

path = '/home/user/Documents/question3/ChallengeImages/'
files = os.listdir(path)

orangeImageCount = 0

for file in files:
    image = utils.read_image(path + file)                                                        
    model = core.Model()
    labels, boxes, scores = model.predict_top(image)
    
    for l in labels:
        if "orange" in l:
            print("Image name: " + path + file)
            print("Label: " + l)
            orangeImageCount +=1
                       
            qr_image = cv2.imread(path + file)
            qr_detect = cv2.QRCodeDetector()
            data = qr_detect.detectAndDecode(qr_image)
            print("QR Code Data: " + data[0])

print("")
print("Orange Image Count: " + str(orangeImageCount))
    

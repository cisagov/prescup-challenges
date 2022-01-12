
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

##################################################################################
#  you must use python3 when running this script to ensure the PIL module loads  #
##################################################################################
from PIL import Image
import sys

#select the image file via command argument
filename = sys.argv[1]
img = Image.open(filename)

#get width and height of image
width = img.width
height = img.height

#################################################################################
#add code here to iterate over the entire width and then the height of the image#
#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv#

colors = img.getpixel((x,y))
print(list(colors))


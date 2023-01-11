
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

print("Enter the coordinates in the following format: A1B:C2D")
coordinates = input("Coordinates: ")

try:
    if coordinates.upper().replace(" ", "") == "DBF:8B7":
        print("Congratulations! You entered the correct coordinates.")
    else:
        print("You entered incorrect coordinate values.")
except:
    print("An exception occurred. Please enter the coordinates in the following format A1B:C2D.")



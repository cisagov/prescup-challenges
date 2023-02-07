
import cv2
import pytesseract
import os
import datetime

path2 = 'galaxies/images2/'

galaxiesFiltered = ["Antennae Galaxy", "Backward Galaxy", "Black Eye Galaxy", "Bodes Galaxy", "Butterfly Galaxies", "Cartwheel Galaxy", "Cigar Galaxy", "Coma Pinwheel Galaxy", "Comet Galaxy", "Cosmos Redshift 7", "Eye of Sauron", "Fireworks Galaxy", "Hockey Stick Galaxy", "Hoags Galaxy", "Large Magellanic Cloud", "Little Sombrero Galaxy", "Medusa Merger", "Sculptor Dwarf Galaxy", "Mice Galaxies", "Small Magellanic Cloud", "Mayalls Object", "Needle Galaxy", "Pinwheel Galaxy", "Sculptor Galaxy", "Sombrero Galaxy", "Southern Pinwheel Galaxy", "Sunflower Galaxy", "Tadpole Galaxy", "Whirlpool Galaxy"]

uniqueGalaxies = []

now = datetime.datetime.now()
print("start date and time: ")
print(str(now))

listing = os.listdir('galaxies/images2/')    
for file in listing:
    img = cv2.imread(path2 + file)    
    text = pytesseract.image_to_string(img)
    
    galaxystring = text.split('\n')
    for g in galaxystring:
        g = g.strip()
        if len(g) > 0:
            #print("galaxy: " + g)
            if g not in uniqueGalaxies:
                uniqueGalaxies.append(g)
            
#print difference between lists
galaxiesFiltered.sort()
uniqueGalaxies.sort()

print("galaxies filtered length: " + str(len(galaxiesFiltered)))
print(galaxiesFiltered)
print("")

print("unique galaxies: " + str(len(uniqueGalaxies)))
print(uniqueGalaxies)
print("")

print("Missing Galaxies")
missing = []
for gal in galaxiesFiltered:
    if gal.upper() not in uniqueGalaxies:
        missing.append(gal.upper())
print(missing)

now = datetime.datetime.now()
print("end date and time: ")
print(str(now))

    

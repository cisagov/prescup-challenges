
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import matplotlib.pyplot as plt
import sys

def plot_letter_with_points(letter_index, x_coords, y_coords, offset, ax, file):
    """Plot a letter with each point numbered and no connecting lines."""
    # Offset x coordinates
    x_coords_offset = [x + offset for x in x_coords]
    
    # Plot points without lines and number them
    for i, (x, y) in enumerate(zip(x_coords_offset, y_coords)):
        ax.scatter(x, y, marker='o', s=100)  # Increased marker size for better visibility
        point_label = f'{letter_index}-{i+1}'
        ax.text(x, y, point_label, fontsize=16, ha='right')
        # Write coordinates to file
        file.write(f'{point_label}: ({x:.2f}, {y:.2f})\n')

def spell_word_on_graph(word, file_path):
    """Spells out a word on an X-Y graph with each point numbered and no lines."""
    # Define a dictionary with more detailed coordinates for each letter
    # ... (Your existing alphabet dictionary) ...
    alphabet = {
        'A': ([0, 0.5, 1, 0.75, 0.25], [0, 3, 0, 1.5, 1.5]),
        'B': ([0, 0, 1, 0, 1, 0], [0, 3, 2.5, 1.5, 0.5, 0]),
        'C': ([1, 0.5, 0, 0.5, 1], [0, 0, 1.5, 3, 3]),
        'D': ([0, 0, 0.5, 1, 1, 0.5, 0], [0, 3, 3, 2.5, 0.5, 0, 0]),
        'E': ([0, 1, 0, 0, 1, 0, 0, 1, 0, 0], [0, 0, 0, 3, 3, 3, 1.5, 1.5, 1.5, 0]),
        'F': ([0, 0, 1, 0, 0, 1, 0, 0], [0, 3, 3, 3, 1.5, 1.5, 1.5, 0]),
        'G': ([1, 0, 0, 1, 1, 0.5], [3, 3, 0, 0, 1.5, 1.5]),
        'H': ([0, 0, 0, 0, 1, 1, 1], [3, 1.5, 0, 1.5, 1.5, 3, 0]),
        'I': ([0.5, 0.5, 0.5, 0.5], [0, 1, 2, 3]),
        'J': ([1, 1, 0, 0], [3, 0, 0, 1]),
        'K': ([0, 0, 0, 0, 1, 0, 1], [3, 1.5, 0, 1.5, 3, 1.5, 0]),
        'L': ([0, 0, 1], [3, 0, 0]),
        'M': ([0, 0, 0.5, 1, 1], [0, 3, 1.5, 3, 0]),
        'N': ([0, 0, 1, 1], [0, 3, 0, 3]),
        'O': ([0, 0, 1, 1, 0], [0, 3, 3, 0, 0]),
        'P': ([0, 0, 1, 1, 0], [0, 3, 3, 2, 2]),
        'Q': ([0, 0, 1, 1, 0, 1, 0.75, 1.25], [0, 3, 3, 0, 0, 0, 0.25, -0.25]),
        'R': ([0, 0, 1, 1, 0, 0.5, 1], [0, 3, 3, 2, 2, 1.5, 0]),
        'S': ([1, 0.5, 0, 0, 0.5, 1, 1, 0.5, 0], [3, 3, 3, 1.5, 1.5, 1.5, 0, 0, 0]),
        'T': ([0.5, 0.5, 0, 1], [0, 3, 3, 3]),
        'U': ([0, 0, 0.5, 1, 1], [3, 0, 0, 0, 3]),
        'V': ([0, 0.5, 1], [3, 0, 3]),
        'W': ([0, 0, 0.5, 1, 1], [3, 0, 1.5, 0, 3]),
        'X': ([0, 1, 0.5, 0, 1], [0, 3, 1.5, 3, 0]),
        'Y': ([0, 0.5, 1, 0.5, 0.5], [3, 1.5, 3, 1.5, 0]),
        'Z': ([0, 1, 0, 1], [3, 3, 0, 0])
        }
    # Open the file to write the coordinates
    with open(file_path, 'w') as file:
        # Create a new figure and axes
        fig, ax = plt.subplots(figsize=(10, 6))

        offset = 0
        for letter_index, letter in enumerate(word.upper(), start=1):
            if letter in alphabet:
                x_coords, y_coords = alphabet[letter]
                plot_letter_with_points(letter_index, x_coords, y_coords, offset, ax, file)
                offset += 4  # Increase offset for the next letter

        # Set the title and labels
        #ax.set_title(f"Word '{word}' with Numbered Points")
        #ax.set_xlabel("X axis")
        #ax.set_ylabel("Y axis")

        # Show the plot with a grid and equal aspect ratio
        #ax.grid(True)
        #ax.axis('equal')
        #plt.show()

# Get the word from command line argument
if len(sys.argv) > 1:
    word = sys.argv[1]
else:
    print("Please provide a word as an argument.")
    sys.exit(1)

# Define the path for the output text file
file_path = '/var/www/html/robots.txt'

# Define the alphabet dictionary with your coordinates for each letter here

# Run the function with the word from command line
spell_word_on_graph(word, file_path)


#!/usr/bin/env python


import itertools
import random
import zipfile
import argparse

# Step 1: Define the possible words for each part of the password
wanted_code_p1 = ["w3", "we", "are", "4r3", "ar3","w4nt3d", "wanted", "w4nted", "want3d"] 
wanted_code_p2 = ["w3", "we", "are", "4r3", "ar3","w4nt3d", "wanted", "w4nted", "want3d"] wanted_code_p3 = ["th3", "the"]
wanted_code_p3 = ["w3", "we", "are", "4r3", "ar3","w4nt3d", "wanted", "w4nted", "want3d"] 

# Step 2: Generate all possible password combinations
def generate_passwords():
    all_possible_combinations = []
    
    for total_words in [3]:
        for combination in itertools.permutations([wanted_code_p1, wanted_code_p2, wanted_code_p3], total_words):
            for words in itertools.product(*combination):
                all_possible_combinations.append(" ".join(words))
    return all_possible_combinations

# Step 3: Generate randomized casing variations
def generate_casing_variations(word):
    """ Generate all possible upper/lowercase variations of a given string """
    variations = []
    for _ in range(8):
        randomized_case = ''.join(char.upper() if random.choice([True, False]) else char.lower() for char in word)
        variations.append(randomized_case)
    return variations

# Step 4: Attempt to crack the ZIP file
def crack_zip(zip_path, password_list):
    with zipfile.ZipFile(zip_path, 'r') as zip_file:
        for password in password_list:
            try:
                zip_file.extractall(pwd=password.encode())
                print(f"✅ Successfully extracted using password: {password}")
                return
            except Exception as e:
                pass  # Ignore incorrect passwords
    print("❌ Failed to extract the ZIP file. None of the passwords worked.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crack a password-protected ZIP file using the generated password list.")
    parser.add_argument("--zipfile", "-z", help="Path to the target ZIP file")
    args = parser.parse_args()
    
    print("🔹 Generating password list...")
    password_variants = []
    for combination in generate_passwords():
        password_variants.extend(generate_casing_variations(combination))
    
    print(f"🔹 Trying {len(password_variants)} passwords against {args.zipfile}...")
    crack_zip(args.zipfile, password_variants)
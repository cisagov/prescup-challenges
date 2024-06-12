#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import requests
import json
import uuid
import random
import os

results = {}

def grade_challenge():
    
    results['GradingCheck1'] = "Fail -- SQL Injection vulnerability was not resolved."
    results['GradingCheck2'] = "Fail -- Authenticated access to files endpoint was not resolved."
    results['GradingCheck3'] = "Fail -- File upload validation was not resolved."
    results['GradingCheck4'] = "Fail -- XSS vulnerability was not resolved."
    
    check1Passed = False
    check2Passed = False
    check3Passed = False
    check4Passed = False
                    
    try:
        check1Passed = check1()
    except:
        results['GradingCheck1'] = "Fail -- Exception occurred while running grading check 1."
        
    try:
        check2Passed = check2()
    except:
        results['GradingCheck2'] = "Fail -- Exception occurred while running grading check 2."
        
    try:
        check3Passed = check3()
    except:
        results['GradingCheck3'] = "Fail -- Exception occurred while running grading check 3."
        
    try:
        check4Passed = check4()
    except:
        results['GradingCheck4'] = "Fail -- Exception occurred while running grading check 4."
                
#############################################################################
            
    if check1Passed:
        results['GradingCheck1'] = "Success -- SQL Injection vulnerability was resolved."
                
    if check2Passed:
        results['GradingCheck2'] = "Success -- Authenticated access to files endpoint was resolved."
        
    if check3Passed:
        results['GradingCheck3'] = "Success -- File upload validation was resolved."
        
    if check4Passed:
        results['GradingCheck4'] = "Success -- XSS vulnerability was resolved."                                   
                                            
    for key, value in results.items():
        print(key, ' : ', value)
        
#############################################################################
        
def setExceptionMessage(check, message):
    if check == "1":
        results['GradingCheck1'] = "Fail -- " + message
    elif check == "2":
        results['GradingCheck2'] = "Fail -- " + message
    elif check == "3":
        results['GradingCheck3'] = "Fail -- " + message
    elif check == "4":
        results['GradingCheck4'] = "Fail -- " + message
        
        
def check1():
    result = checkSQLInjection()
    return result
        
def check2():
    result = checkAuthenticatedAccess()
    return result
       
def check3():
    result = checkFileUpload()
    return result
        
def check4():
    result = checkXSS()
    return result
                                                                                                            
def checkSQLInjection():
    
    # test sql with or 1=1;--
    # if we get more than one result in the json array, sql injection worked 
    
    try:
        # start by adding an item and querying for it, 
        # to make sure valid queries will work
        
        guid = str(uuid.uuid4())
        randomNumber = str(random.randint(1,1000000))
        name = "Item " + randomNumber
        desc = "Description " + randomNumber
        itemCount = str(random.randint(1, 500))
        
        DATA = {"Id":guid, "Name":name, "Description":desc, "Count":itemCount}
        HEADERS = {'content-type':'application/json'}
        r = requests.post(url = "http://10.1.1.201/api/inventory/addinventoryitem", data = str(json.dumps(DATA)), headers = HEADERS)
        data = str(r.json())
        if "true" not in data.lower():
            print("check failed. test item could not be added.")
            return False        
        
        PARAMS = {'searchTerm':name}
        r = requests.get(url = "http://10.1.1.201/api/inventory/searchinventory", params = PARAMS)
        data = str(r.json())
        if name not in data:
            print("check failed. valid item not found.")
            return False
        else:
            print("valid item was found.")
        
        # test to see if sql injection works on searchinventory 
        url = "http://10.1.1.201/api/inventory/getinventoryitems"
        
        r = requests.get(url = url)
        data = str(r.json())  
    
        data = data[1:]
        data = data[:-1]    
    
        item_dict = data.split("}, {")
        count1 = len(item_dict)
    
        url = "http://10.1.1.201/api/inventory/searchinventory"
        PARAMS = {"searchTerm":"' or 31245057=31245057;--"}
        r = requests.get(url = url, params = PARAMS)
        
        data = str(r.json())
        data = data[1:]
        data = data[:-1]
        item_dict = data.split("}, {")
        count2 = len(item_dict)
    
        if count1 == count2:
            print("check failed. sql injection was allowed.")
            return False
        else:
            print("check passed. sql injection attack failed.")
            return True 
    except Exception as e:
        setExceptionMessage("1", f"EXCEPTION - {e}")
        print(f"EXCEPTION - {e}")
        return False 


def checkAuthenticatedAccess():
    try:
        url2 = "http://10.1.1.201/api/files/getfiles"
        r = requests.get(url = url2)
        data = str(r.json())
        
        if data.startswith("[") and data.endswith("]"):
            print("check failed. unauthenticated call succeeded.")
            return False
        
        check1 = False
        check2 = False
            
        #add code here to handle unauthorized error
        if "statuscode" in data.lower() and "401" in data:
            print("authenticated call required.")
            check1 = True
            
        #make authenticated call
        HEADERS = {"ApiKey":"6FE88482-03B9-40A8-AF2D-14D7FD6843BA-8015E4C1-8DA6-4286-B6B9-BA3E12350876", "UserId":"84e897b6-fadb-4df1-904c-ffcc162e9cd2", "UserEmail":"test@test.com"}        
        r = requests.get(url = url2, headers = HEADERS)
        data = str(r.json())
        
        if data.startswith("[") and data.endswith("]"):
            print("check passed. authenticated API call succeeded.")
            check2 = True
            
        if check1 == True and check2 == True:
            return True
        else:
            return False
    except Exception as e:
        setExceptionMessage("2", f"EXCEPTION - {e}")
        print(f"EXCEPTION - {e}")
        return False   


def checkFileUpload():
    
    try:
        url4 = "http://10.1.1.201/api/files/uploadfile"
        # file must be less than 1,000,000 bytes and not have an exe extension
        
        fileSizeInBytes = 100000
        with open("test.pdf", "wb") as fout:
            fout.write(os.urandom(fileSizeInBytes))
            
        with open("test.pdf", "rb") as postedFile:
            files = {"file": postedFile}
            response = requests.post(url4, files = files)
            
            if response.text.lower() != "true":
                print("check failed. valid file upload failed.")
                return False
                    
        fileSizeInBytes = 1100000 
        with open("test.exe", "wb") as fout:
            fout.write(os.urandom(fileSizeInBytes)) 
        
        with open("test.exe", "rb") as postedFile:
            files = {"file": postedFile}
            response = requests.post(url4, files = files)
            
            if response.text.lower() == "true":
                print("check failed. file larger than 1,000,000 bytes was uploaded.")
                return False
                
        fileSizeInBytes = 1024
        with open("tiny.exe", "wb") as fout:
            fout.write(os.urandom(fileSizeInBytes)) 
        
        with open("tiny.exe", "rb") as postedFile:
            files = {"file": postedFile}
            response = requests.post(url4, files = files)
            
            if response.text == "true":
                print("check failed. exe file upload was allowed.")
                return False
         
        print("check passed. file validation worked.")       
        return True
                
    except Exception as e:
        setExceptionMessage("3", f"EXCEPTION - {e}")
        print(f"EXCEPTION - {e}")
        return False

    
def checkXSS():
    
    # add an item to the database
    # get all items, checking for script name
    # if it is not encoded, return false
        
    try:
        url3 = "http://10.1.1.201/api/inventory/addinventoryitem"
        #add item with script tags
        guid = str(uuid.uuid4())
        randomNumber = str(random.randint(1,1000000))
        name = "<script>alert('" + randomNumber + "');</script>"
        desc = "Description " + randomNumber
        itemCount = str(random.randint(1, 500))
        
        DATA = {"Id":guid, "Name":name, "Description":desc, "Count":itemCount}
        headers = {'content-type':'application/json'}
        
        r = requests.post(url = url3, data = str(json.dumps(DATA)), headers = headers)
        
        url3 = "http://10.1.1.201/api/inventory/getinventoryitems"
        r = requests.get(url = url3)
        data = str(r.json())  
                
        if guid in data and name in data and desc in data:
            print("check failed. the data was not html encoded.")
            return False

        if "<script>" not in data and "&lt;script&gt;" in data and guid in data:
            print("check passed. the data was html encoded.")
            return True
        else:
            print("check failed. the data was not html encoded.")
            return False
      
    except Exception as e:
        setExceptionMessage("4", f"EXCEPTION - {e}")
        print(f"EXCEPTION - {e}")
        return False    
        

if __name__ == '__main__':
    grade_challenge()

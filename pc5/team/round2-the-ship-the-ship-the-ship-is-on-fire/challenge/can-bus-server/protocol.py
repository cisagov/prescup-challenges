
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# modify the protocol.py file that is included with the can_remote python package
# by default this code is installed here:
# /home/user/.local/lib/python3.11/site-packages/can_remote/protocol.py
# insert the code below after line 38 in protocol.py
# when the correct message is discovered the canbus_complete.txt file is created
# the grading script will check for the presence of canbus_complete.txt to determine
# that the correct data was sent to the server

# expected arbitration_id=0xa1223a
# original data=[70, 60, 30, 80, 50, 20, 10, 40]
try:
    if os.path.exists("/home/user/Documents/canbus_complete.txt") is False:
        customData = str(data)
        if str(hex(arb_id)) == "0xa1223a":
            print("***** The antenna arbitration_id has been transmitted. *****")
            val1 = False
            val2 = False
            val3 = False
            val4 = False
            val5 = False
            val6 = False
            val7 = False
            val8 = False

            print("data lenght: " + str(len(data)))

            for b in data:                                
                s = str(hex(b))
                i = int(s, 0)
                s = str(i)                                
                print(s)

                if "81" == s:
                    val1 = True
                
                if "71" == s:
                    val2 = True
                    
                if "41" == s:
                    val3 = True
                    
                if "91" == s:
                    val4 = True

                if "61" == s:
                    val5 = True
                
                if "31" == s:
                    val6 = True
                    
                if "21" == s:
                    val7 = True
                    
                if "51" == s:
                    val8 = True
        
            if (val1 == True and val2 == True and val3 == True and val4 == True and
                val5 == True and val6 == True and val7 == True and val8 == True):
                f = open("/home/user/Documents/canbus_complete.txt", "a")
                f.write("Custom Data Message: " + customData + "\n")
                f.write("arb_id: " + str(hex(arb_id)) + "\n")
                f.close()

                print("***** Correct custom data has been transmitted: " + customData + " *****")
except:
    print("An error occurred in protocol.py while parsing custom challenge data.")

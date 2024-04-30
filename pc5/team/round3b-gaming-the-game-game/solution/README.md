# Gaming the Game: Game

*Solution Guide*

## Overview

You are given a client to a game. The game client can be edited so the game can be completed faster. You have to beat the game faster than what is on the scoreboard.

Download the game client, **game_client.py**, from `challenge.us/files`. Play the game manually to fully understand how to "speed run" the game. Make sure to put the correct IP address, `10.5.5.5`, into the game client.

## Question 1

*After completing the "time" quest, what is the "Time" token received?*

Completing this quest is straightforward. There's an `elf` room where you `talk_to_elf` to get some gold. However, there is a one hour cool-down timer before you can talk to the elf again. To repeat this quest, change the time sent by:

- Adding an hour to your machine and send the time to the server; or
- Using `datetime` to add an hour and send the time to the server.

After changing the time, repeat the quest until you can buy an item. After purchasing this item, you can retrieve the flag.

After downloading `game_client.py`, you can play the game by opening a terminal and typing the following command: 

```bash
python3 game_client.py
```

Completing this quest is straightforward. Once you start the game, you will notice there are a couple of rooms: `time`, `treasure`, `key`, `elf`, `north`, `east` and `west`. We are told that it is recommended to play the game in order to understand how to beat the game. This is what we will be doing in this part of the solution guide: 

1. First, we will go to the `north` room: 

```
north
```

2. Once you go `north`, you will receive a message saying the there is a note on the table. Read it using `read_note`:

```
read_note
```

You will receive a three digit code. Write this code down. This code is dynamic and might be different in your deployment. In our case, the code was `572`. 

3. Next, go to the `treasure` room by typing the following: 

```
treasure
```

4. This room will show you a message saying that you can use `open_chest` to try to open the chest. Let's try that:

```
open_chest
```

It is giving us three attempts to open the chest. 

5. Enter the 3 digit code you found earlier. In our case, it was 572. 

```
572
```

You have found a treasure. 

6. Let's now jump to the `key` room.

```
key
```

7. In this room, you are provided with a puzzle you need to solve. In order to start solving it, you need to type `solve_puzzle`. Let's do that: 

```
solve_puzzle
```

8. You are displayed the puzzle: "The puzzle: What has keys but can't open locks?"

The answer to this question is `a piano.`

9. Let's now jump to the `elf` room. 

```
elf
```

After entering the `elf` room, you are told you can either talk to the elf by typing `talk_to_elf` or, buy an item by typing `buy_item`. It also let's you know there is a digital clock next to the elf. 

10. Let's try talking to the elf: 

```
talk_to_elf
```

Great, we received 100 pieces of gold. 

11. Now, let's see if we can buy some items: 

```
buy_item
```

You are told to come back with more gold. 

12. Try talking again to the elf and see if we get more free gold:

```
talk_to_elf
```

We are told that we already received our free gold and, we need to come in an hour.

13. There is one room called `time`. Let's see if going to this room provides some guidance: 

```
time
```

14. Inside this room, you are given two new options: `check_time` and `change_time`. Let's check the time first: 

```
check_time
```
As expected, this will show the current time. 

15. If you try typing `change_time`, you will see a message saying "Sending current time...". 


If you take a closer look at the `game_client.py`, you can notice that line 27 is sending the current time. We might be able to tamper with the VM time to trick the server. Let's try that. 

16. In a new terminal, enter the following command to increase time by an hour: 

```bash
sudo date --set="$(date -d '+1 hour')"
```

17. Now, let's try changing the time in the game. Go back to the terminal were the game is live and type: 

```
change_time
```

18. Check the time again: 

```
check_time
```

The time of the game has increased by one hour! 

19.  Now that the game thinks that one hour has passed, let's try talking to the elf again: 

```
talk_to_elf
```

You were given 100 more coins! 

For the purpose of this solution guide, we know that you need 500 coins to be able to buy the required item so, perform step 13 to 16 four more times until you have 500 total coins. 

20. Once you have 500 coins, you can execute the following command: 

```
buy_item
```

Once you buy the item, you will receive a scroll displaying the first flag! 

21. Go to `https://challenge.us` and paste the first flag in the first text box to initiate grading. 

22. To beat the game, the only thing left will be to run: 

```
beat_game
```

This will show you that you completed the game but, that that you don't have the top score. Next part is beating the score!


## Question 2

*After beating the top score, what is the "Final" token received? *

You might've noticed in the first part that there are three different components to this game that must be completed as fast as possible:

1. Opening the chest puzzle
2. Solving the riddle puzzle
3. Buying the item from the elf puzzle

It is very unlikely you will be able to beat this part manually. However, since you are given the game client script, you can make some modifications to it to send the server each required entry. Here is a python script that helps you achieve this part as quick as possible. 

>NOTE: Remember that our three-digit code might be different than yours, Make sure you change it in the code below: 

```python
#! /bin/python3  
import socket 
import os 
from time import sleep 
from datetime import datetime, timedelta  

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
client.connect(("10.5.5.5",9999))  

response_messages = [] 
sleeps = 0.05
code = "572"  

def get():     
    sleep(sleeps)     
    response = client.recv(4096).decode()     
    return response  

def put(val):     
    sleep(sleeps)     
    print(">{}".format(val))     
    client.send(val.encode()) 
    
def start():     
    result = get()     
    print(result)        
    
def chest():     
    result = ""         
        
    while not "3 attempts" in result:         
        put("open_chest")         
        result = get()         
        print(result)      
        
    while not "Congratulations" in result:         
        put(code)         
        result = get()         
        print(result)  
        
def riddle():     
    result = ""     
    # this next part is for the riddle     
    # need to get it work for input though     
    while not "Congrat" in result:        
       
        while not "The puzzle" in result:             
            put("solve_puzzle")             
            result = get()             
            print(result)          
        
        put("piano")         
        result = get()         
        print(result)  


def elf():
    # Talk to the elf once
    put("talk_to_elf")
    result = get()
    print(result)
    
    # Now simulate the time change request by explicitly calling 'change_time'
    put("change_time")  # This is to simulate the act of requesting to change the time
    result = get()  # Assuming this get() is necessary to fetch any immediate response before updating time
    # Increase time by 5 hours
    new_time = datetime.now() + timedelta(hours=5)
    new_time_str = new_time.strftime('%Y-%m-%d %H:%M:%S')
    put(new_time_str)  # Send the updated time after 'change_time' command
    result = get()
    print(f"Time changed to {new_time_str}")
    print(result)
    
    # Proceed with talking to the elf four more times
    for _ in range(4):
        put("talk_to_elf")
        result = get()
        print(result)
    
    # After completing the interactions and time change, proceed to buy the item
    put("buy_item")
    result = get()
    print(result)

start() 
chest() 
riddle() 
elf() 
put("beat_game") 
result = get() 
print(result) 
```

After pasting the script above in a file, feel free to name it however you want. Remember this is a python script. We called it: `my_game_client.py`. 

1. Run your own game client: 

```bash
python3 my_game_client.py
```

It will start running and once it finishes it will show you your new position in the score board. You will also receive the last flag! 

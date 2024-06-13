
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#! /bin/python3
import socket
import datetime
import threading
import random
import time as clock
import subprocess

token1 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.time'", shell=True, capture_output=True).stdout.decode('utf-8').strip()
token2 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.speed'", shell=True, capture_output=True).stdout.decode('utf-8').strip()


# Define the game's rooms and actions
rooms = {
    "start": "You are in a dark room. There is a door to the north. There's also doors labeled treasure, time, and key.\n",
    "north_room": "You have entered a room with a large table. There is a note on the table. There is a door to the east and a door to the west.\nYou can always try to read_note.\n",
    "east_room": "You are in a library filled with books. There is a door to the west.\n",
    "west_room": "You are in a garden with colorful flowers. There is a door to the east.\n",
    "treasure_room": "You've found a room with a glittering treasure chest! Use open_chest to try to open the chest.\n",
    "key_room": "You've entered a room with a locked door. There is a note on the table that reads, 'To unlock the door, solve the puzzle: What has keys but can't open locks?'\nTry solve_puzzle to solve!\n",
    "elf_room": "There's an elf with a bag of gold on a table and a digital clock right next to it.\nTry talk_to_elf! He also might have items, try buy_item.\n",
    "time_room": "There's a strange feeling in this room. Almost like it's timeless.\nTry to check_time or change_time.\n",
    "end": "Congratulations! You have reached the end of the game.\n",
    "game_over": "Time's up! Game over. Thanks for playing!\n"
}

actions = {
    "north": "north_room",
    "east": "east_room",
    "west": "west_room",
    "treasure": "treasure_room",
    "key": "key_room",
    "elf": "elf_room",
    "time": "time_room",
    "quit": "end",
    "open_chest": "treasure_room",
    "solve_puzzle": "key_room"
}

hiscore = {
    "ET": 10,
    "AMV": 20,
    "SPACE_COWBOY": 50,
    "LT": 60
}

# Initialize puzzle variables
combination = [random.randint(1, 9) for _ in range(3)]
combination_str = ''.join(str(num) for num in combination)
puzzle_solution = ("a piano", "piano")

game_duration = 600 # Number in seconds
# winner_flag = "fca168"

# Function to handle a client's connection
def handle_client(client_socket):
    current_room = "start"
    start_time = clock.time()
    last_quest_completion = None
    last_quest_completion_stripped = None
    treasure_room_complete = 0
    item_obtained = 0
    puzzle_solved = 0
    client_time = datetime.datetime.now()
    winner = 0
    gold = 0
    
    client_socket.send("Welcome! If you have enough treasures, please type beat_game.\n".encode())

    while current_room != "end":
        elapsed_time = int(clock.time() - start_time)
        if elapsed_time >= game_duration:
            client_socket.send(f"Total time taken: {elapsed_time} seconds.\n".encode())
            client_socket.send(rooms["game_over"].encode())
            client_socket.close()
            return
        
        client_socket.send(rooms[current_room].encode())
        user_input = client_socket.recv(1024).decode().lower()
        

        if user_input == "open_chest":
            if treasure_room_complete == 1:
                client_socket.send("Treasure chest is empty. You have the treasure already.\n".encode())
                current_room = "start"
            else:
                attempts = 3
                client_socket.send("You've found a treasure chest with a combination lock!\n".encode())
                client_socket.send("You can open_chest or close_chest.\n".encode())
                client_socket.send(f"You have {attempts} attempts to open it.\n".encode())
                while attempts > 0:
                    user_combination = client_socket.recv(1024).decode()
                    if user_combination == "close_chest":
                        client_socket.send("You closed the chest, resetting the attempts.\n".encode())
                        current_room = "start"
                        attempts = 3
                        break
                    if user_combination.isdigit() and len(user_combination) == 3:
                        #user_combination = list(map(int, user_combination))
                        if user_combination == combination_str:
                            client_socket.send("Congratulations! You've unlocked the chest and found a valuable treasure!\nAdding this to your total number of treasures!\n".encode())
                            treasure_room_complete = 1
                            current_room = "start"
                            break
                        else:
                            client_socket.send("Incorrect combination. Try again.\n".encode())
                            attempts -= 1
                    else:
                        client_socket.send("Invalid input. Enter a 3-digit combination.\n".encode())
                else:
                    client_socket.send("You've run out of attempts. The chest remains locked\n".encode())
                    current_room = "start"
                    attempts = 3
        elif user_input == "solve_puzzle":
            if puzzle_solved == 1:
                client_socket.send("You solved the puzzle already!\n".encode())
                current_room = "start"
            else:
                client_socket.send("The puzzle: What has keys but can't open locks?\n".encode())
                answer = client_socket.recv(1024).decode().lower()
                if answer in puzzle_solution:
                    client_socket.send("Congratulations! You've solved the puzzle.\n".encode())
                    puzzle_solved = 1
                    current_room = "start"
                else:
                    client_socket.send("That's not the correct answer. The door remains locked.\n".encode())
        elif user_input == "read_note":
            client_socket.send(f"You found the combination to the chest: {combination_str}\n".encode())
            if treasure_room_complete == 1:
                client_socket.send(f"You shouldn't need the combination. You already have the treasure.\n".encode())
        elif user_input == "talk_to_elf":
            if last_quest_completion is None or (client_time - last_quest_completion).seconds >= 3600:
                client_socket.send("Free daily quest completed! Here's 100 pieces of gold!\n".encode())
                gold += 100
                client_socket.send(f"You currently have {gold} pieces of gold.\n".encode())
                last_quest_completion = datetime.datetime.now()
                last_quest_completion_stripped = last_quest_completion.strftime('%Y-%m-%d %H:%M:%S')
                last_quest_completion_stripped = datetime.datetime.strptime(last_quest_completion_stripped, '%Y-%m-%d %H:%M:%S')
            else:
                client_socket.send("You've already claimed your free gold! Please wait one hour.\n".encode())
        elif user_input == "buy_item":
            if gold >= 500:
                client_socket.send(f"I can't believe you have that much gold! Here's your item!\nIt's a scroll that reads: \"Time token: {token1}\".\n".encode())
                item_obtained = 1
            else:
                client_socket.send("Come back with more gold...\n".encode())
                current_room = "start"
        elif user_input == "change_time":
            client_socket.send("request_time".encode())
            client_time = client_socket.recv(1024).decode().lower()
            client_time = datetime.datetime.strptime(client_time, '%Y-%m-%d %H:%M:%S')
            print(client_time)
        elif user_input == "check_time":
            client_socket.send(f"Current time is {client_time}.\n".encode())
        elif user_input == "beat_game":
            if item_obtained == 1 and puzzle_solved == 1 and treasure_room_complete == 1:
                client_socket.send("You have won the game! Congratulations!\n".encode())
                client_socket.send(f"You beat the game in {elapsed_time}.\n".encode())
                hiscore["Challenger"] = elapsed_time
                sorted_scores = dict(sorted(hiscore.items(), key=lambda x: x[1]))
                
                if list(sorted_scores.keys())[0] == "Challenger":
                    client_socket.send(f"NEW HIGH SCORE! YOU HAVE THE NEW TOP SCORE! Here's the final token: {token2}\n".encode())
                else:
                    # Check if Challenger beat any of the existing high scores but is not the top scorer
                    if elapsed_time < hiscore[list(sorted_scores.keys())[1]]:
                        client_socket.send("NEW HIGH SCORE! But not the top score.\n".encode())
                    else:
                        client_socket.send("Not fast enough. Try again.\n".encode())

                # Always send the sorted high scores back to the client
                client_socket.send(f"Scoreboard: {sorted_scores}\n".encode())

            else:
                client_socket.send("You are missing treasures. Try again when you have enough treasures.\n".encode())
        elif user_input in actions:
            current_room = actions[user_input]
        else:
            client_socket.send("Invalid input. Try again.\n".encode())
            
    if winner == 1:
        # client_socket.send(f"{winner_flag}".encode())
        client_socket.send(f"Bye.".encode())
    client_socket.send("Game over. Thanks for playing!".encode())
    client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9999))
server.listen(5)

print("Server listening on port 9999")

while True:
    client_socket, addr = server.accept()
    print(f"Accepted connection from {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()


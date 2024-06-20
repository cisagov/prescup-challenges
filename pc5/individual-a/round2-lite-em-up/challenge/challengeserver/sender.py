#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import shutil
import zipfile
import time
import random
import subprocess
import os
import pickle

time.sleep(45)

for i in range(5):

    time.sleep(5)

    # Load the lone wolf data from the stored file
    lone_wolf_data_file = "/home/user/challenge/lone_wolf_data.pkl"
    if os.path.exists(lone_wolf_data_file):
        with open(lone_wolf_data_file, "rb") as f:
            lone_wolf = pickle.load(f)
    else:
        lone_wolf = None

    # Define the list of people and their Litecoin addresses
    people = [
        "alice:rltc1qd5ysug9gqhkglq6tkj08xnt5yxed9cgn8plufe",
        "bob:rltc1qaela3a6yphyedks59lyxcw0ufscwz4pfarnth2",
        "charlie:rltc1q602ugt034ss4jnppdecgut4xmducl3ssxvtjfq",
        "daisy:rltc1qh992xsmtujez8ccyd23jy9pmulqs08ch7jufhx",
        "ethan:rltc1qwpfe2p0het9sp5wyhwdklf55fhpfmq5chm7nyk",
        "fiona:rltc1q05md77uwmjnn3grx6mkjuhmkdmhe4d407sq6dd",
        "george:rltc1q7j2puj0r58uvvyd5gvamq9q7ss0a0ku6yd89se",
        "hannah:rltc1qtjj70r3e0d5gqszra6lx38v37d02pwm6kd3y90",
        "ivan:rltc1quphsmm0m2keql8ccf6j6vrruptgwdg5dk5my3l",
        "jade:rltc1qyt54ql2q8ndx8xgu83ncqys6u8r3ctstgjg3vs",
        "kevin:rltc1qfallfuvncjsz9jwkwgzfy4xh7kaq9l3g6u6kxm",
        "lily:rltc1q0mzpqnr0756saltxmsuaprf4zk5p8d9arhuf9v",
        "max:rltc1qmalupa2c5ftekdq4x6azrdczpgzj23x337gvwk",
        "nora:rltc1qmelnx8tn78t0xe6jrkl2trnfdzumasy054pm9t",
        "oscar:rltc1qw27r49mnmqvwv80rz28m2xcf8h7z8qxjy88wwf",
        "penelope:rltc1qv97sks6dmratc2rg4zrprfnw8fh9c3cr6netkh",
        "quentin:rltc1qdctdshv22mfg3cp27rc7hc4dme7yc3p00yrt3z",
        "rachel:rltc1qt4wmhn436n0xc9nzg4ujpp6pzm3ztwy7dkjuqv",
        "sam:rltc1q56jldn046lvda6hdl92l3szz54ljml8hs655l2",
        "tina:rltc1qmf0sr457mlne8yxhwqwn8v00w0hztztdqtkfey",
        "ulysses:rltc1qx4a9f9pmun4ytvmk44s08gstg4my7sz88r35nw",
        "victor:rltc1qyle2fxn6wsmquef6md8tnuwnwdrevmwfsrpnlk",
        "wendy:rltc1qsakd5tnxzczewft8cc9v4dtkj48lz89lpzd04a",
        "xavier:rltc1q872ec3jjxcxv572zmck60ntqvpyvr9fuepm8zh",
        "yara:rltc1qa0g5ecgveg988lawrpnuy83mnwpwn3qdkjuh5q",
    ]

    # Check if the group data file exists
    group_data_file = "/home/user/challenge/group_data.pkl"
    if os.path.exists(group_data_file):
        # If the file exists, load the stored groups and lone wolf
        with open(group_data_file, "rb") as f:
            data = pickle.load(f)
            if len(data) == 2:
                groups, lone_wolf = data
                last_group_index = 0  # Set default value for last_group_index
            else:
                groups, lone_wolf, last_group_index = data
    else:
        # If the file doesn't exist, shuffle the list of people to create groups and a possible lone wolf
        random.shuffle(people)

        # Calculate the number of groups and the size of the last group (if there's a lone wolf)
        num_people = len(people)
        num_groups = num_people // 3
        size_last_group = num_people % 3

        # Ensure the last group has 3 people
        if size_last_group != 0:
            num_groups += 1
            num_people_last_group = num_people - (num_groups - 1) * 3
            lone_wolf = people[-1]
            if num_people_last_group == 1:
                # Add two people from the previous group to form a group of 3
                people[-2:-1] += [people[-2], people[-3]]
            elif num_people_last_group == 2:
                # Add one person from the previous group to form a group of 3
                people[-2:-1] += [people[-2]]
            # Remove the lone wolf from the shuffled list
            people = people[:-1]
            num_people -= 1
        else:
            lone_wolf = None

        # Assign people into groups
        groups = [people[i:i + 3] for i in range(0, num_people, 3)]

    # Load the wallets for each person
    for person in people:
        name, _ = person.split(":")
        try:
            # Check if the wallet is already loaded
            command = f"litecoin-cli -regtest listwallets | grep {name}_wallet"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if name + "_wallet" not in result.stdout:
                # If the wallet is not loaded, load it
                command = f"litecoin-cli -regtest loadwallet {name}_wallet"
                subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while loading wallet for {name}: {e}")
            continue

    # Shuffle all transactions except for the lone wolf transaction
    all_transactions = [(person, buddy) for group in groups for person in group for buddy in group if person.split(":")[1] != buddy.split(":")[1]]
    random.shuffle(all_transactions)

    # Get the group index for the lone wolf to send transactions
    if lone_wolf:
        group_index_to_send = random.randint(0, len(groups) - 1)
        last_group_index = (group_index_to_send + 1) % len(groups)
    else:
        group_index_to_send = None

    # Store the receiver's name and address for the lone wolf transaction
    lonewolf_receiver_name = None
    lonewolf_receiver_address = None
    lone_wolf_sent = False

    # Execute the shuffled transactions
    for transaction in all_transactions:
        sender_name, sender_address = transaction[0].split(":")
        receiver_name, receiver_address = transaction[1].split(":")
        try:
            # Execute the Litecoin transaction between the sender and receiver
            coins = round(random.uniform(0.5, 5), 2)
            command = f"litecoin-cli -regtest -rpcwallet={sender_name}_wallet sendtoaddress {receiver_address} {coins}"
            subprocess.run(command, shell=True, check=True)
            print(f"{sender_name} sent {coins} LTC to {receiver_name}")

            # Check if the receiver is the one who received LTC from the lone wolf
            if group_index_to_send is not None and lonewolf_receiver_name and lonewolf_receiver_address:
                if receiver_name == lonewolf_receiver_name:
                    # Execute the Litecoin transaction between the receiver and the lone wolf
                    coinsrx = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.coinsrx'", shell=True, capture_output=True) # one of these vlues at random; 2.57 2.59 2.61 2.63 2.65 2.67 2.69 2.71 2.73 2.75 2.77 2.79 2.81 2.83 2.85 2.87 2.89 2.91 2.93 2.95 2.97 2.99 3.01 3.03 3.05 3.07 3.09 3.11 3.13 3.15 3.17 3.19 3.21 3.23 3.25 3.27 3.29 3.31 3.33 3.35 3.37 3.39 3.41 3.43 3.45 3.47 3.49 3.51 3.53 3.55 3.57 3.59 3.61 3.63 3.65 3.67 3.69 3.71 3.73 3.75 3.77 3.79 3.81 3.83 3.85 3.87 3.89 3.91 3.93 3.95 3.97 3.99 4.01 4.03 4.05 4.07 4.09 4.11 4.13 4.15
                    coinsrx = coinsrx.stdout.decode('utf-8').strip()
                    command = f"litecoin-cli -regtest -rpcwallet={receiver_name}_wallet sendtoaddress {lone_wolf.split(':')[1]} {coinsrx}"
                    subprocess.run(command, shell=True, check=True)
                    print(f"{receiver_name} sent {coinsrx} LTC back to {lone_wolf.split(':')[0]} (Lone Wolf)")
                    lonewolf_receiver_name = None
                    lonewolf_receiver_address = None
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while sending transaction between {sender_name} and {receiver_name}: {e}")
            continue

        # Check if the lone wolf should send funds in this iteration
        if group_index_to_send is not None and not lone_wolf_sent and random.random() < 0.5:
            lonewolf_group = groups[group_index_to_send]
            receiver_name, receiver_address = random.choice(lonewolf_group).split(":")
            try:
                # Execute the Litecoin transaction between the lone wolf and the receiver
                coinstx = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.coinstx'", shell=True, capture_output=True) # one of these values at random; 0.81 0.83 0.85 0.87 0.89 0.91 0.93 0.95 0.97 0.99 1.01 1.03 1.05 1.07 1.09 1.11 1.13 1.15 1.17 1.19 1.21 1.23 1.25 1.27 1.29 1.31 1.33 1.35 1.37 1.39 1.41 1.43 1.45 1.47 1.49 1.51 1.53 1.55 1.57 1.59 1.61 1.63 1.65 1.67 1.69 1.71 1.73 1.75 1.77 1.79 1.81 1.83 1.85 1.87 1.89 1.91 1.93 1.95 1.97 1.99
                coinstx = coinstx.stdout.decode('utf-8').strip()
                command = f"litecoin-cli -regtest -rpcwallet={lone_wolf.split(':')[0]}_wallet sendtoaddress {receiver_address} {coinstx}"
                subprocess.run(command, shell=True, check=True)
                print(f"{lone_wolf.split(':')[0]} (Lone Wolf) sent {coinstx} LTC to {receiver_name}")
                lonewolf_receiver_name = receiver_name
                lonewolf_receiver_address = receiver_address
                lone_wolf_sent = True
            except subprocess.CalledProcessError as e:
                print(f"Error occurred while sending transaction between {lone_wolf.split(':')[0]} (Lone Wolf) and {receiver_name}: {e}")

    # Update the last_group_index and store in the data file for future script executions
    with open(group_data_file, "wb") as f:
        pickle.dump((groups, lone_wolf, last_group_index), f)

    # Print the lone wolf
    if lone_wolf:
        print(f"Lone Wolf: {lone_wolf}")


directory = '/home/user/.litecoin'
destination_directory='/home/user/challengeServer/hosted_files'
zip_filename = 'regtest'

shutil.make_archive(os.path.join(destination_directory, zip_filename), 'zip', directory)

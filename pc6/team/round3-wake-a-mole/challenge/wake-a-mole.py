#!/usr/bin/env python3
import socket
import threading
import random
import os
import pty
import struct
import sys
import time

# === SETTINGS ===
PORT = 9999

# Difficulty settings: used for flavor (taunts and adjusting difficulty)
HARD_MODE_THRESHOLD = 2   # Game gets harder after 2 failed attempts
RESET_DIFFICULTY = 5      # Difficulty resets after 5 failed attempts

# Global game state (for flavor)
player_attempts = 0       # Tracks player failures
difficulty_level = 1      # 1 = Easy, 2 = Hard, 3 = Expert

# === FUNCTIONS TO BE HIJACKED ===
def secret_mole_escape(client_socket):
    """
    The function that spawns a shell. It should only be called if the attacker
    correctly overwrites the function pointer.
    """
    message = "\n🐹 MOLE ESCAPED! SYSTEM COMMAND EXECUTING...\n"
    try:
        client_socket.sendall(message.encode())
    except Exception:
        pass
    # Duplicate client socket FD to standard I/O and spawn a shell.
    fd = client_socket.fileno()
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.execv("/bin/bash", ["/bin/bash"])

def safe_escape(client_socket):
    """
    The safe default function that gets called if the attacker fails to
    overwrite the function pointer correctly.
    """
    message = "\n🐹 Mole says: No escape this time! Better luck next round!\n"
    try:
        client_socket.sendall(message.encode())
    except Exception:
        pass

# === DIFFICULTY ADJUSTMENT & TAUNTS (Flavor) ===
def adjust_difficulty():
    global player_attempts, difficulty_level
    if HARD_MODE_THRESHOLD <= player_attempts < RESET_DIFFICULTY:
        difficulty_level = 2  # Hard Mode
    elif player_attempts >= RESET_DIFFICULTY:
        difficulty_level = 1  # Reset Difficulty
        player_attempts = 0

taunts_easy = [
    "🐹 Mole says: You missed! Try again! \n",
    "🐹️Mole says: Haha, too slow! \n",
    "🐹️Mole says: Is that all you got? \n",
]

taunts_hard = [
    "🐹️Mole says: Are you even trying?! \n",
    "🐹 Mole says: Maybe hacking isn't for you. \n",
    "🐹 Mole says: I changed memory layout, try again! \n",
]

taunts_expert = [
    "🐹 Mole says: I'm evolving! You will never win. \n",
    "🐹 Mole says: Go read more PWN tutorials! \n",
    "🐹 Mole says: Time to rage quit? \n",
]

# === DEBUG CANARY LEAK (Flavor) ===
def debug_canary_leak(client_socket):
    """
    Simulate a partial stack canary leak by generating a random 64-bit value.
    """
    canary = random.getrandbits(64)
    leak_msg = f"\n🐹 Konami Code: {canary:x}\n"
    client_socket.sendall(leak_msg.encode())

# === DYNAMIC ADDRESS GENERATION & FORMAT STRING SIMULATION ===
def get_real_addresses():
    """
    Obtain a list of addresses for several functions using Python's id().
    One of these (the one for secret_mole_escape) is the valid target.
    The order is randomized each connection.
    """
    addresses = [
        id(secret_mole_escape),
        id(adjust_difficulty),
        id(debug_canary_leak),
        id(play_mole_game),
        id(start_mole_service)
    ]
    random.shuffle(addresses)
    return addresses

def simulate_format_string(fmt):
    """
    Simulate a vulnerable printf by replacing every '%p' in the user-provided
    format string with one of our dynamically generated addresses.
    """
    addresses = get_real_addresses()
    result = ""
    pos = 0
    ptr_index = 0
    while pos < len(fmt):
        if fmt[pos:pos+2] == "%p":
            if ptr_index < len(addresses):
                result += hex(addresses[ptr_index])
                ptr_index += 1
            else:
                result += "0x0"
            pos += 2
        else:
            result += fmt[pos]
            pos += 1
    return result

# === MAIN GAME FUNCTION (VULNERABLE ROUTINE) ===
def play_mole_game(client_socket):
    global player_attempts, difficulty_level
    shell_spawned = False
    try:
        # Initialize the function pointer to the safe default.
        mole_escape = safe_escape

        # --- Stage 1: Welcome and Canary Leak ---
        welcome = "\n🐹️ Welcome to Wake-A-Mole! 🐹\n"
        client_socket.sendall(welcome.encode())
        debug_canary_leak(client_socket)

        # --- Stage 2: Format String Vulnerability ---
        prompt1 = "⬇️ Select a mole hole (1-9): \n"
        client_socket.sendall(prompt1.encode())
        user_input = client_socket.recv(1024).decode().strip()
        # Expand any '%p' specifiers in the input.
        formatted_output = simulate_format_string(user_input)
        client_socket.sendall((formatted_output + "\n").encode())

        # --- Stage 3: Randomized Buffer Overflow ---
        # Randomize the vulnerable buffer size (simulate between 100 and 150 bytes)
        rand_buffer_size = random.randint(100, 150)
        # Randomize the offset where the function pointer is stored (buffer + 4 to buffer + 20)
        pointer_offset = rand_buffer_size + random.randint(4, 20)
        overflow_length = pointer_offset + 8  # total bytes read includes the pointer overwrite

        prompt2 = "\n⚡️ Select a power-up (Speed/Strength): \n"
        client_socket.sendall(prompt2.encode())
        # Read exactly overflow_length bytes from the client.
        overflow_input = client_socket.recv(overflow_length)

        # --- Stage 4: Check the Overflow Payload ---
        if len(overflow_input) >= pointer_offset + 8:
            new_ptr = overflow_input[pointer_offset:pointer_offset+8]
            overwritten_ptr = struct.unpack("<Q", new_ptr)[0]
            # Only if the attacker overwrote the pointer with the exact address
            # of secret_mole_escape do we update it.
            if overwritten_ptr == id(secret_mole_escape):
                mole_escape = secret_mole_escape

        if mole_escape == secret_mole_escape:
            shell_spawned = True

        # --- Stage 5: Trigger the (Potentially Hijacked) Function Pointer ---
        mole_escape(client_socket)

        # --- Stage 6: Taunting & Difficulty Adjustment (Flavor) ---
        player_attempts += 1
        adjust_difficulty()
        if difficulty_level == 1:
            taunt = random.choice(taunts_easy)
        elif difficulty_level == 2:
            taunt = random.choice(taunts_hard)
        else:
            taunt = random.choice(taunts_expert)
        client_socket.sendall(taunt.encode())

    except Exception as e:
        print("Error in play_mole_game:", e)
    finally:
        if not shell_spawned:
            try:
                client_socket.close()
            except Exception:
                pass

# === SOCKET SERVER FUNCTION ===
def start_mole_service():
    """Starts the main mole service and continuously accepts connections."""
    while True:
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("", PORT))
            server_socket.listen(5)
            print(f"🐹 Mole Game Service started on port {PORT}")
            
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    print(f"🌍 New connection from: {addr[0]}")
                    # Each connection is handled in a separate thread.
                    client_handler = threading.Thread(target=play_mole_game, args=(client_socket,))
                    client_handler.daemon = True
                    client_handler.start()
                except Exception as conn_err:
                    print("Error accepting connection:", conn_err)
                    continue
        except Exception as serv_err:
            print("Critical server error:", serv_err)
        finally:
            try:
                server_socket.close()
            except Exception:
                pass
            # Restart the service after a brief pause if it crashes.
            print("Restarting Mole Game Service...")
            time.sleep(1)

if __name__ == "__main__":
    start_mole_service()


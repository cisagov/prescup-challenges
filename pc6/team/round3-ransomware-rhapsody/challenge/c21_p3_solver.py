import os
import itertools
import string
import argparse
import re

def xor_decrypt_large_file(encrypted_file, output_file, key, chunk_size=4096, preview_size=500):
    """Decrypts an XOR-encrypted file in chunks for large files and extracts readable text."""
    key_bytes = key.encode()
    key_length = len(key_bytes)

    # Get file size
    file_size = os.path.getsize(encrypted_file)
    print(f"🔍 Processing large file: {encrypted_file} ({file_size} bytes)")

    # Read and decrypt in chunks
    decrypted_data = bytearray()
    key_cycle = itertools.cycle(key_bytes)  # Cycle the key

    with open(encrypted_file, "rb") as f_in, open(output_file, "wb") as f_out:
        while chunk := f_in.read(chunk_size):  # Read file in chunks
            decrypted_chunk = bytes([b ^ next(key_cycle) for b in chunk])  # XOR decryption
            decrypted_data.extend(decrypted_chunk)
            f_out.write(decrypted_chunk)  # Write decrypted chunk to output file

    print(f"✅ Decrypted file saved as '{output_file}'")

    # === Extract Readable Text ===
    readable_text = ''.join(chr(b) if chr(b) in string.printable else '.' for b in decrypted_data)

    # Search for possible credential-like patterns
    potential_strings = re.findall(r"[\w@#.$%^&*!-]{4,50}", readable_text)

    if potential_strings:
        print("\n🔍 Potential Credential Candidates:")
        for idx, candidate in enumerate(potential_strings[:10], 1):  # Show top 10 candidates
            print(f"{idx}. {candidate}")

        print("\n⚠️ No strict format assumed—manual verification needed.")
    else:
        print("⚠️ No readable credentials detected.")

    # Optional: Show preview of readable content based on --preview argument
    print(f"\n🔍 Preview of readable content (first {preview_size} characters):")
    print(re.sub(r"[^\x20-\x7E]", ".", readable_text[:preview_size]))  # Show limited preview based on user input

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a large XOR-encrypted file and extract plaintext credentials.")
    parser.add_argument("-i", "--input", required=True, help="Path to the encrypted file")
    parser.add_argument("-o", "--output", required=True, help="Path to save the decrypted file")
    parser.add_argument("-k", "--key", required=True, help="Decryption key (must match encryption key)")
    parser.add_argument("-c", "--chunk", type=int, default=4096, help="Chunk size for processing large files (default: 4096 bytes)")
    parser.add_argument("-p", "--preview", type=int, default=500, help="Number of readable text characters to preview (default: 500)")

    args = parser.parse_args()
    
    xor_decrypt_large_file(args.input, args.output, args.key, args.chunk, args.preview)

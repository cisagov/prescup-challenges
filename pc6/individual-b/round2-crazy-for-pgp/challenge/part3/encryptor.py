def xor_bytes(data, key):
    """Perform XOR between two byte sequences of the same length."""
    return bytes([b ^ k for b, k in zip(data, key)])


def pad(data, block_size):
    """Pads the data to be a multiple of the block size using PKCS#7."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad(data):
    """Removes PKCS#7 padding."""
    padding_len = data[-1]
    return data[:-padding_len]


def cbc_encrypt(plaintext, key, iv):
    """
    Encrypts plaintext using CBC mode with XOR-based "encryption."
    :param plaintext: Input plaintext (bytes)
    :param key: Encryption key (bytes), length must match block size
    :param iv: Initialization vector (bytes), length must match block size
    :return: Encrypted ciphertext (bytes)
    """
    block_size = len(iv)
    if len(key) != block_size:
        raise ValueError("Key length must match block size (IV length).")

    plaintext = pad(plaintext, block_size)
    ciphertext = b""
    previous_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # XOR plaintext block with previous block
        encrypted_block = xor_bytes(block, previous_block)
        # XOR result with key to "encrypt" the block
        encrypted_block = xor_bytes(encrypted_block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    """
    Decrypts ciphertext using CBC mode with XOR-based "decryption."
    :param ciphertext: Encrypted data (bytes)
    :param key: Encryption key (bytes), length must match block size
    :param iv: Initialization vector (bytes), length must match block size
    :return: Decrypted plaintext (bytes)
    """
    block_size = len(iv)
    if len(key) != block_size:
        raise ValueError("Key length must match block size (IV length).")

    plaintext = b""
    previous_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        # XOR block with key to "decrypt" the block
        decrypted_block = xor_bytes(block, key)
        # XOR result with previous block to retrieve plaintext
        decrypted_block = xor_bytes(decrypted_block, previous_block)
        plaintext += decrypted_block
        previous_block = block

    return unpad(plaintext)


# Example usage
if __name__ == "__main__":
    # 4-byte IV and key
    iv = b"\x01\x02\x03\x04"
    key = b"\x0A\x0B\x0C\x0D"

    # Plaintext to encrypt
    plaintext = b"Hello, CBC mode!"

    # Encrypt
    ciphertext = cbc_encrypt(plaintext, key, iv)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_text = cbc_decrypt(ciphertext, key, iv)
    print("Decrypted text:", decrypted_text.decode())


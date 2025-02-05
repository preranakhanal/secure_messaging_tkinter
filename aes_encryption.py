def aes_encrypt(data, key):
    """Encrypts data using a basic AES-like block cipher."""
    BLOCK_SIZE = 16  # Similar to AES block size
    encrypted_data = bytearray()
    key = key.ljust(BLOCK_SIZE, b'\x00')[:BLOCK_SIZE]  # Ensure key size

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        block = block + b'\x00' * (BLOCK_SIZE - len(block))  # Pad block
        encrypted_block = bytearray((block[j] ^ key[j]) for j in range(BLOCK_SIZE))  # XOR encryption
        encrypted_block = encrypted_block[::-1]  # Simple permutation (reversal)
        encrypted_data.extend(encrypted_block)

    return bytes(encrypted_data)

def aes_decrypt(data, key):
    BLOCK_SIZE = 16  # Similar to AES block size
    """Decrypts data using a basic AES-like block cipher."""
    decrypted_data = bytearray()
    key = key.ljust(BLOCK_SIZE, b'\x00')[:BLOCK_SIZE]  # Ensure key size

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE][::-1]  # Reverse permutation
        decrypted_block = bytearray((block[j] ^ key[j]) for j in range(BLOCK_SIZE))  # XOR decryption
        decrypted_data.extend(decrypted_block)

    return bytes(decrypted_data).rstrip(b'\x00')  # Remove padding


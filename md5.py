def key_generation_hash(data):
    """A simple hash function for key derivation, expanded to 16 bytes."""
    data = bytearray(data)  # Convert input to byte array
    hash_value = 0xABCD  # Initialize with a fixed value (like a seed)

    for byte in data:
        hash_value = ((hash_value << 5) | (hash_value >> 11)) & 0xFFFF  # Rotate left 5 bits
        hash_value ^= byte  # XOR with data byte

    # Convert 16-bit hash to bytes and expand it to 16 bytes by repeating it
    hash_bytes = hash_value.to_bytes(2, 'little') * 8  # Repeat the 2-byte hash 8 times
    return hash_bytes  # Now it's 16 bytes

import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HEADER_SIZE = 54
BLOCK_SIZE = 16


def my_ecb(path: str, mode: chr, key=None):
    if mode != 'e' and mode != 'd':
        exit("Invalid mode!")
    if mode == 'd' and key is None:
        exit("You must pass a key in decrypt mode!")
    if key is None:
        # Generate a random key (16 bytes/128 bits)
        key = get_random_bytes(BLOCK_SIZE)
    print('Your key is: '+str(key))
    # Create a new cipher suite with this key
    cipher = AES.new(key, AES.MODE_ECB)

    # Open the image
    img = open(path, "rb")
    # Set up a counter for the bytes left to read from the image
    bytes_left = os.fstat(img.fileno()).st_size
    # Skim off the header for safekeeping
    header = img.read(HEADER_SIZE)
    # Decrement bytes_left since we just took off the header
    bytes_left -= HEADER_SIZE

    # Create the output file. Fails if it already exists, and opens in binary mode.
    output = None
    if mode == 'e':
        output = open(path.replace(".bmp", "") + "_encrypted.bmp", "xb")
    else:
        output = open(path.replace(".bmp", "") + "_decrypted.bmp", "xb")
    output.write(header)

    while bytes_left > 0:
        # Figure out how many bytes to read from the file. Either a full block or everything left.
        bytes_to_read = BLOCK_SIZE if bytes_left >= BLOCK_SIZE else bytes_left
        bytes_left -= bytes_to_read

        # Read unprocessed block
        block = img.read(bytes_to_read)

        # Pad if necessary, PKCS#7 compliant (hopefully lol)
        block += (16-bytes_to_read).to_bytes(1, byteorder='big') * (16-bytes_to_read)

        # Process and knock off padding
        block_processed = cipher.encrypt(block) if mode == 'e' else cipher.decrypt(block)
        block_processed = block_processed[:bytes_to_read]

        # Write the processed block
        output.write(block_processed)

    img.close()
    output.close()

    return key


def my_cbc(path: str, mode: chr, key=None, iv=None):
    if mode != 'e' and mode != 'd':
        exit("Invalid mode!")
    if mode == 'd' and (key is None or iv is None):
        exit("You must pass a key and IV in decrypt mode!")
    if key is None:
        # Generate a random key (16 bytes/128 bits)
        key = get_random_bytes(BLOCK_SIZE)
    if iv is None:
        iv = get_random_bytes(BLOCK_SIZE)
    print('Your key is: '+str(key))
    print('Your IV is: '+str(iv))
    # Create a new cipher suite with this key
    cipher = AES.new(key, AES.MODE_ECB)

    # Open the image
    img = open(path, "rb")
    # Set up a counter for the bytes left to read from the image
    bytes_left = os.fstat(img.fileno()).st_size
    # Skim off the header for safekeeping
    header = img.read(HEADER_SIZE)
    # Decrement bytes_left since we just took off the header
    bytes_left -= HEADER_SIZE

    # Create the output file. Fails if it already exists, and opens in binary mode.
    output = None
    if mode == 'e':
        output = open(path.replace(".bmp", "") + "_encrypted.bmp", "xb")
    else:
        output = open(path.replace(".bmp", "") + "_decrypted.bmp", "xb")
    output.write(header)

    prev_block = None

    while bytes_left > 0:
        # Figure out how many bytes to read from the file. Either a full block or everything left.
        bytes_to_read = BLOCK_SIZE if bytes_left >= BLOCK_SIZE else bytes_left
        bytes_left -= bytes_to_read

        # Read unprocessed block
        block = img.read(bytes_to_read)

        # Pad if necessary, PKCS#7 compliant (hopefully lol)
        block += (16-bytes_to_read).to_bytes(1, byteorder='big') * (16-bytes_to_read)
        if mode == 'e':
            if prev_block is None:
                block = xor(block, iv)
            else:
                block = xor(block, prev_block)
        # Process and knock off padding
        block_processed = cipher.encrypt(block) if mode == 'e' else cipher.decrypt(block)
        block_processed = block_processed[:bytes_to_read]

        if mode == 'd':
            if prev_block is None:
                block_processed = xor(block_processed, iv)
            else:
                block_processed = xor(block_processed, prev_block)

        # Write the processed block
        output.write(block_processed)
        prev_block = block_processed if mode == 'e' else block

    img.close()
    output.close()

    return key, iv


def xor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


if __name__ == '__main__':
    my_ecb("mustang.bmp", 'e')
    # my_ecb("mustang_encrypted.bmp", 'd', b'\xe8[xg\x9e\x0e^\xc0\x89_J\xad\xf6\x17\x9a\xea')
    # my_cbc("mustang.bmp", 'e')
    # my_cbc("mustang_encrypted.bmp", 'd', b'\x91\xcdma\x1c\x9f\\\x9e\xc2l8\x01F\t\xb2?', b'(\xc1\xe2\xfb\x1dE`\xe8\\\xa4\x9b+\xe7\x81\x9a@')

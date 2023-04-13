import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HEADER_SIZE = 54
BLOCK_SIZE = 16


def my_encrypt_ecb(path: str):
    # Generate a random key (16 bytes/128 bits)
    key = get_random_bytes(16)
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
    output = open(path.replace(".bmp", "") + "_encrypted.bmp", "xb")
    output.write(header)

    while bytes_left > 0:
        bytes_to_read = BLOCK_SIZE if bytes_left >= BLOCK_SIZE else bytes_left
        bytes_left -= bytes_to_read

        block = img.read(bytes_to_read)

        block += b'\x00' * (16-bytes_to_read)

        block_encrypted = cipher.encrypt(block)

        block_encrypted = block_encrypted[:bytes_to_read]

        # TODO: add handling for block length < 128 (padding scheme)

        output.write(block_encrypted)

    img.close()
    output.close()


if __name__ == '__main__':
    my_encrypt_ecb("mustang.bmp")
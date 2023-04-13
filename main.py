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
        # Figure out how many bytes to read from the file. Either a full block or everything left.
        bytes_to_read = BLOCK_SIZE if bytes_left >= BLOCK_SIZE else bytes_left
        bytes_left -= bytes_to_read

        # Read unencrypted block
        block = img.read(bytes_to_read)

        # Pad if necessary, PKCS#7 compliant (hopefully lol)
        block += (16-bytes_to_read).to_bytes(1, byteorder='big') * (16-bytes_to_read)

        # Encrypt and knock off padding
        block_encrypted = cipher.encrypt(block)[:bytes_to_read]

        # Write the encrypted block
        output.write(block_encrypted)

    img.close()
    output.close()


if __name__ == '__main__':
    my_encrypt_ecb("mustang.bmp")
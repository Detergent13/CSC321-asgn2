from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image

HEADER_SIZE = 54


def my_encrypt_ecb(path: str):
    # Generate a random key
    key = get_random_bytes(128)
    # Create a new cipher suite with this key
    cipher = AES.new(key, AES.MODE_ECB)

    # Open the image
    img = Image.open(path)
    # Set up a counter for the bytes left to read from the image
    bytes_left = img.getsize()
    # Skim off the header for safekeeping
    header = img.read(HEADER_SIZE)
    # Decrement bytes_left since we just took off the header
    bytes_left -= HEADER_SIZE

    # Create the output file. Fails if it already exists, and opens in binary mode.
    output = open(path.replace(".bmp", "") + "_encrypted.bmp", "xwb")
    output.write(header)

    # test 2

    while bytes_left > 0:
        bytes_to_read = 128 if bytes_left >= 128 else bytes_left
        bytes_left -= bytes_to_read

        block = img.read(bytes_to_read)

        block_encrypted = cipher.encrypt(block)

        # TODO: add handling for block length < 128 (padding scheme)

        output.write(block_encrypted)

    img.close()
    output.close()

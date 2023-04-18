import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
key = get_random_bytes(BLOCK_SIZE)
iv = get_random_bytes(BLOCK_SIZE)

def submit(userString: str):
    # prepend and append string to userString
    plaintext = "userid=456;userdata=" + userString + ";session-id=31337"
    # URL encoding
    plaintext = plaintext.replace("=", "%3D")
    plaintext = plaintext.replace(";", "%3B")
    # cast cipherText to bytes
    plaintext = plaintext.encode()
    # pad text using PKCS#7 padding
    plaintext += (16 - (len(plaintext) % 16)).to_bytes(1, byteorder='big') * (16 - (len(plaintext) % 16))
    # encrypt using CBC
    cipherText = my_cbc(plaintext)
    return cipherText

def verify(encrypted_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_text).decode('utf-8', "ignore")
    return ';admin=true;' in decrypted_message

def my_cbc(plaintext):
    # Create a new cipher suite with this key
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = None
    # num bytes left to encrypt
    bytes_left = len(plaintext)
    cipherText = b''

    while bytes_left > 0:
        bytes_left -= BLOCK_SIZE
        # reads first block of plaintext into block
        block = plaintext[:16]
        # removes first block of plaintext from plaintext
        plaintext = plaintext[16:]

        # first block read
        if prev_block is None:
            block = xor(block, iv)
        else:
            block = xor(block, prev_block)

        # encrypted block stored in block_processed
        block_processed = cipher.encrypt(block)

        # store current encrypted block to xor with next block
        prev_block = block_processed

        # concatenate block to cipherText
        cipherText += block_processed
    return cipherText

def xor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

if __name__ == '__main__':
    ciphertext = submit("1234567admin1true1")

    # convert bytes to bytearray to allow indexing
    ciphertext = bytearray(ciphertext)
    ciphertext[16] = ciphertext[16] ^ ord("7") ^ ord(";")
    ciphertext[22] = ciphertext[22] ^ ord("1") ^ ord("=")
    ciphertext[27] = ciphertext[27] ^ ord("1") ^ ord(";")
    # convert back to bytes
    ciphertext = bytes(ciphertext)

    # check if ";admin=true;" was in the decrypted text
    if (verify(ciphertext)): print("hacker wins")
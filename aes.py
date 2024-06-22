import sys

# helper arrays of sbox and inverse sbox for encryption and decryption
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# main aes encryption function, reads files and encrypts message using helper functions
def aes():
    # get script arguments
    args = sys.argv[1:]
    # save paths in variables
    enc_or_dec = args[0]
    msg_path = args[1]
    key_path = args[2]
    out_path = args[3]
    # check if encryption or decryption
    if enc_or_dec == '-e':
        output = encrypt(msg_path, key_path) # encrypt message
    elif enc_or_dec == '-d':
        output = decrypt(msg_path, key_path) # decrypt message
    else:
        return # if invalid argument, return
    # write cipher to file as bytes
    with open(out_path, 'wb') as f:
        f.write(output)

# encryption algorithm: sub_bytes -> shift_rows -> rotate -> add_round_key -> sub_bytes -> shift_rows -> rotate -> add_round_key
def encrypt(msg_path, key_path):
    # read files as bytes
    with open(msg_path, 'rb') as f:
        msg = f.read()
    with open(key_path, 'rb') as f:
        key = f.read()
    # divide message into blocks
    msg_blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    # divide key into blocks
    key_blocks = [key[i:i+16] for i in range(0, len(key), 16)]
    # create new message array for encryption
    new_msg = []
    # iterate over blocks and encrypt using first key
    for block in msg_blocks:
        block = bytearray(block)
        # sub_bytes
        block = sub_bytes(block)
        # shift_rows
        block = shift_rows(block)
        # rotate 90 degrees clockwise
        block = rotate(block)
        # add_round_key
        block = add_round_key(block, key_blocks[0])
        # sub_bytes
        block = sub_bytes(block)
        # shift_rows
        block = shift_rows(block)
        # rotate 90 degrees clockwise
        block = rotate(block)
        # add_round_key
        block = add_round_key(block, key_blocks[1])
        # append encrypted block to new message
        new_msg.append(block)
    # concatenate blocks to one message
    enc_msg = b''.join(new_msg)
    # encryption algorithm
    return enc_msg

# decryption algorithm, same as encryption but in reverse order: add_round_key -> rotate -> shift_rows -> sub_bytes -> add_round_key -> rotate -> shift_rows -> sub_bytes
def decrypt(cipher_path, key_path):
    # read files as bytes
    with open(cipher_path, 'rb') as f:
        cipher = f.read()
    with open(key_path, 'rb') as f:
        key = f.read()
    # divide cipher into blocks
    msg_blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
    # divide key into blocks
    key_blocks = [key[i:i+16] for i in range(0, len(key), 16)]
    # create new message array for decryption
    new_msg = []
    # iterate over blocks and decrypt using first key
    for block in msg_blocks:
        # create new block array
        block = list(block)
        # convert each byte to bytes-like object
        block = [bytes([b]) for b in block]
        # add_round_key
        block = add_round_key(block, key_blocks[1])
        # rotate 90 degrees clockwise
        block = rotate(block,False)
        # shift_rows
        block = shift_rows(block, False)
        # sub_bytes
        block = sub_bytes(block, False)
        # convert to bytes again
        block = [bytes([b]) for b in block]
        # add_round_key
        block = add_round_key(block, key_blocks[0])
        # rotate 90 degrees clockwise
        block = rotate(block, False)
        # shift_rows
        block = shift_rows(block, False)
        # sub_bytes
        block = sub_bytes(block, False)
        # convert to string
        block = bytes(block)
        # append encrypted block to new message
        new_msg.append(block)
    # concatenate blocks to one message
    dec_msg = b''.join(new_msg)
    # return decrypted message
    return dec_msg

# helper functions for encryption/decryption algorithm: substitute bytes
# if encryption, uses s_box, if decryption, uses inv_s_box
def sub_bytes(block, enc=True):
    # iterate each byte in block
    if enc: # if encryption, substitute with s_box
        for i in range(16):
                block[i] = s_box[block[i]]
    else: # if decryption, substitute with inv_s_box
        # flatten block
        block = [byte for row in block for byte in row]
        # iterate each byte in block and substitute value
        for i in range(16):
            block[i] = inv_s_box[block[i]]
    # return block
    return block

# helper functions for encryption/decryption algorithm
# if encryption, shift row in direction of index, if decryption, shift row in opposite direction
def shift_rows(block, enc=True):
    if enc: # if encryption
        # convert block to matrix
        block = [block[i:i+4] for i in range(0, len(block), 4)]
    # iterate over rows
    for i in range(4):
        if enc:
            # shift row in direction of index
            block[i] = block[i][i:] + block[i][:i]
        else:
            # shift row in opposite direction
            block[i] = block[i][4-i:] + block[i][:4-i]
    # return block
    return block

# helper functions for encryption/decryption algorithm: rotate
# if encryption, rotates block 90 degrees clockwise, if decryption, rotates block 90 degrees counter-clockwise
def rotate(block, enc=True):
    if enc: # if encryption
        # rotate block 90 degrees clockwise by transposing and reversing
        block = list(zip(*block[::-1]))
        # convert each row to bytes
        block = [bytes(row) for row in block]
    else: # if decryption
        # convert block to matrix
        block = [block[i:i + 4] for i in range(0, len(block), 4)]
        # rotate block 90 degrees counter-clockwise by transposing and reversing
        block = list(zip(*block))[::-1]
    # return block
    return block

# helper functions for encryption/decryption algorithm: add_round_key
# XOR block with key to encrypt/decrypt
def add_round_key(block, key):
    '''
    XOR block with key
    :return:
    ByteArray of block XOR key
    '''
    # convert block to bytes
    block = b''.join(block)
    # XOR block with key, bitwise
    block = bytearray(b1 ^ b2 for b1, b2 in zip(block, key))
    return block

# helper function to test aes encryption script
def run_aes(msg_path, key_path):
    # encrypt message
    cipher = encrypt(msg_path, key_path)
    # write cipher to file as bytes in utf-8
    with open("encrypt.txt", 'wb') as f:
        f.write(cipher)
    # decrypt message
    dec_msg = decrypt("encrypt.txt", key_path)
    # write decrypted message to file as bytes in utf-8
    with open("decrypted.txt", 'wb') as f:
        f.write(dec_msg)

# test function for short message, reads short message and key from file and runs aes encryption
# and decryption, then compares the results to the answer files
def test_short():
    msg_path = "C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\message_short.txt"
    key_path = "C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\keys_short.txt"
    run_aes(msg_path, key_path)
    # read cipher from file as bytes
    with open("encrypt.txt", 'rb') as f:
        cipher = f.read()
    # read answer file
    with open("C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\cipher_short.txt", 'rb') as f:
        answer = f.read()
    # check if cipher is correct
    if cipher == answer:
        print("Short Encryption Correct")
    else:
        print("Short Encryption Incorrect")
    # read decrypted message from file as bytes
    with open("decrypted.txt", 'rb') as f:
        dec_msg = f.read()
    # compare decrypted message to original message
    with open(msg_path, 'rb') as f:
        msg = f.read()
    if dec_msg == msg:
        print("Short Decryption Correct")
    else:
        print("Short Decryption Incorrect")

# test function for long message, reads long message and key from file and runs aes encryption
# and decryption, then compares the results to the answer files
def test_long():
    msg_path = "C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\message_long.txt"
    key_path = "C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\keys_long.txt"
    cipher_path = "C:\\Users\Lior\Downloads\TestFilesQues2\TestFilesQues2\cipher_long.txt"
    run_aes(msg_path, key_path)
    # read cipher from file as bytes
    with open("encrypt.txt", 'rb') as f:
        cipher = f.read()
    # read answer file
    with open(cipher_path, 'rb') as f:
        answer = f.read()
    # check if cipher is correct
    if cipher == answer:
        print("Long Encryption Correct")
    else:
        print("Long Encryption Incorrect")
    # read decrypted message from file as bytes
    with open("decrypted.txt", 'rb') as f:
        dec_msg = f.read()
    # compare decrypted message to original message
    with open(msg_path, 'rb') as f:
        msg = f.read()
    if dec_msg == msg:
        print("Long Decryption Correct")
    else:
        print("Long Decryption Incorrect")

# test function to run short and long tests
def test():
    test_short()
    test_long()


if __name__ == '__main__':
    # test()
    aes()
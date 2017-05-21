from Crypto.Cipher import AES
from Crypto.Cipher.AES import AESCipher
from Crypto import Random
from Crypto.PublicKey import RSA

import os
import time

IV_BLOCK_SIZE = 16
CHUNK_SIZE = 1024


def file_encrypt(key, file):
    """
    :param infile: file which should be encrypted
    :param key: AES CFB encryption method will be used
    """

    with open(name=file, mode="rb+") as opened_file:

        IV = Random.new().read(IV_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CFB, IV)

        size_added = 0
        while True:
            data = opened_file.read(CHUNK_SIZE)
            if not data:
                break

            cipher_data = cipher.encrypt(plaintext=data)
            opened_file.seek(size_added)
            opened_file.write(cipher_data)
            size_added += len(cipher_data)

        # write IV at the end of file
        opened_file.write(IV)
    return


def file_decrypt(key, file):
    """
    :param filename: file which should be decrypted
    :param outfilename: output file name
    :param key: AES CFB encryption method will be used
    """

    with open(name=file, mode="rb+") as opened_file:
        size_added = 0

        start_time = time.time()
        # read IV from the end of the file
        opened_file.seek(-IV_BLOCK_SIZE, os.SEEK_END)
        IV = opened_file.read(IV_BLOCK_SIZE)
        opened_file.seek(-IV_BLOCK_SIZE, os.SEEK_END)
        opened_file.truncate()
        opened_file.seek(0) # get back to the start position
        cipher = AES.new(key, AES.MODE_CFB, IV)
        elapsed_time = time.time() - start_time
        print("Time elapsed while getting IV: " + str(elapsed_time))

        while True:
            data = opened_file.read(CHUNK_SIZE)
            if not data:
                break

            plain_data = cipher.decrypt(ciphertext=data)
            opened_file.seek(size_added)
            opened_file.write(plain_data)
            size_added += len(plain_data)
    return


def generate_rsa_keys(filename):
    """
    Generates an RSA key pair default size in 2048 bits
    If a previous file exists same name it overwrites to those files
    Therefore, it is suggested to check it before creating new keys.
    File format will be as for public keys filename_pub.pem, and
    for private keys filename_priv.pem.
    :param filename:
    :return:
    """
    rsa_key = RSA.generate(bits=2048)
    public_exponent = rsa_key.publickey().exportKey("PEM")
    private_exponent = rsa_key.exportKey("PEM")

    # write public key
    pubkey_file_name = filename + "_pub.pem"
    with open(name=pubkey_file_name, mode="w") as pubkey_file:
        pubkey_file.write(public_exponent)

    # write private key
    privkey_file_name = filename + "_priv.pem"
    with open(name=privkey_file_name, mode="w") as privkey_file:
        privkey_file.write(private_exponent)

    return


def text_encrypt(data, key):
    cipher = AESCipher(key=key)
    print cipher.encrypt(data)
    return

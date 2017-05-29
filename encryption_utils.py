from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import os
import hashlib
from file_utils import FileUtils

IV_BLOCK_SIZE = 16
CHUNK_SIZE = 1024


class EncryptionUtils:
    def __init__(self):
        return

    @staticmethod
    def file_encrypt(key, file):
        """
        :param file: file which should be encrypted
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

    @staticmethod
    def file_decrypt(key, file):
        """
        :param file: file which should be decrypted
        :param key: AES CFB encryption method will be used
        """

        with open(name=file, mode="rb+") as opened_file:
            size_added = 0

            # read IV from the end of the file
            opened_file.seek(-IV_BLOCK_SIZE, os.SEEK_END)
            IV = opened_file.read(IV_BLOCK_SIZE)
            opened_file.seek(-IV_BLOCK_SIZE, os.SEEK_END)
            opened_file.truncate()
            opened_file.seek(0)  # get back to the starting position
            cipher = AES.new(key, AES.MODE_CFB, IV)

            while True:
                data = opened_file.read(CHUNK_SIZE)
                if not data:
                    break

                plain_data = cipher.decrypt(ciphertext=data)
                opened_file.seek(size_added)
                opened_file.write(plain_data)
                size_added += len(plain_data)
        return

    @staticmethod
    def rsa_generate(keypath, keyname, passphrase):
        """
        Generates an RSA key pair default size in 2048 bits
        If a previous file exists same name it overwrites to those files
        Therefore, it is suggested to check it before creating new keys.
        File format will be as for public keys filename_pub.pem, and
        for private keys filename_priv.pem.
        :param filename:
        :param passphrase in order to export private key encrypted with 3DES
        :return:
        """
        rsa_key = RSA.generate(bits=2048)
        public_exponent = rsa_key.publickey().exportKey("PEM")
        private_exponent = rsa_key.exportKey(format="PEM", passphrase=passphrase)
        rsa_key.exportKey()

        # write public key
        pubkey_file_name = os.path.join(keypath, (keyname + "_pub.pem"))

        FileUtils.write_data_to_file(filename=pubkey_file_name, data=public_exponent)

        # write private key
        privkey_file_name = os.path.join(keypath, (keyname + "_priv.pem"))

        FileUtils.write_data_to_file(filename=privkey_file_name, data=private_exponent)
        return

    @staticmethod
    def rsa_encrypt(public_key_file_name, data):
        """
        Encrypt with rsa public key
        :param public_key_file_name: file name to use to encrypt
        :param data: data that will be encrypted
        :return: byte array that is encrypted in base64 form,
        in case of error None
        """

        # read pub key from file
        public_key = FileUtils.read_data_from_file(filename=public_key_file_name)

        if public_key is not None:
            rsa_public_key = RSA.importKey(externKey=public_key)
            return base64.encodestring(rsa_public_key.encrypt(plaintext=data, K=12)[0])
        return None

    @staticmethod
    def rsa_decrypt(private_key_file_name, cipher_base64, passphrase):
        """
        Decrpyt with rsa private key
        :param private_key_file_name:
        :param cipher_base64: will be decrypted should be provided in base64 form
        :param passphrase in order to open encrypted private key
        :return: plain text will be returned
        """
        cipher_decoded = base64.decodestring(cipher_base64)

        private_key = FileUtils.read_data_from_file(filename=private_key_file_name)

        if private_key is not None:
            rsa_private_key = RSA.importKey(externKey=private_key, passphrase=passphrase)
            return rsa_private_key.decrypt(ciphertext=cipher_decoded)
        return None

    @staticmethod
    def rsa_sign(private_key_file_name, data, passphrase):
        """
        Perform signing with rsa private key
        :param private_key_file_name:
        :param data:
        :param passphrase:
        :return:
        """

        private_key = FileUtils.read_data_from_file(filename=private_key_file_name)

        if private_key is not None:
            rsa_private_key = RSA.importKey(externKey=private_key, passphrase=passphrase)
            # k is a random value does not effect the functionality
            signature = rsa_private_key.sign(M=data, K=12)[0]
            return base64.encodestring(str(signature))
        return None

    @staticmethod
    def rsa_verify(public_key_file_name, data, signature):
        """
        Perform signing with rsa private key
        :param public_key_file_name:
        :param data to validate the signature of
        :param signature: should be provided in base64 format
        :return: bool if signing is ok, True, False
        """

        public_key = FileUtils.read_data_from_file(filename=public_key_file_name)

        signature = long(base64.decodestring(signature))

        if public_key is not None:
            rsa_public_key = RSA.importKey(externKey=public_key)
            return rsa_public_key.verify(M=data, signature=(signature,))
        return False

    @staticmethod
    def sha256(data):
        return hashlib.sha256(data)

    @staticmethod
    def check_rsa_priv_passphase(priv_key_file_name, passphrase):
        private_key_data = FileUtils.read_data_from_file(filename=priv_key_file_name)
        try:
            rsa_priv_key = RSA.importKey(externKey=private_key_data, passphrase=passphrase)
            return True
        except Exception, e:
            print(str(e))
            return False

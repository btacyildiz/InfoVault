from file_utils import FileUtils
from encryption_utils import EncryptionUtils
from Crypto import Random
import base64
import json
import os.path


class FileVault:
    def __init__(self, keydirectory, keyname, dirname):
        """
        :param keyname: <keyname>_priv.pem <keyname>_pub.pem
        :param dirname: directory which will be encrypted or decrypted
        """
        self._keydirectory = keydirectory
        self._pubkey = keyname + "_pub.pem"
        self._privkey = keyname + "_priv.pem"
        self._dirname = dirname
        self._symmetrickey = ""

    def encrypt_callback(self, filename):
        print FileUtils.read_data_from_file(filename=filename)
        EncryptionUtils.file_encrypt(key=self._symmetrickey, file=filename)
        return

    def decrypt_callback(self, filename):
        EncryptionUtils.file_decrypt(key=self._symmetrickey, file=filename)
        print FileUtils.read_data_from_file(filename=filename)
        return

    def encrypt(self, passphrase):
        # first create a 256 bit AES key
        key_size = 32 # bytes

        # first check if provided public & private keys are exists.
        pubkeydirectory = os.path.join(self._keydirectory, self._pubkey)
        if not os.path.isfile(path=pubkeydirectory):
            print("Public key file is not found under " + pubkeydirectory)
            return

        # first check if provided public & private keys are exists.
        privkeydirectory = os.path.join(self._keydirectory, self._pubkey)
        if not os.path.isfile(path=privkeydirectory):
            print("Public key file is not found under " + privkeydirectory)
            return

        # check passphrase of private key


        self._symmetrickey = Random.get_random_bytes(key_size)
        # encryption is performed via provided callback function
        FileUtils.walk_in_directory(directory=self._dirname, callback=self.encrypt_callback)

        # create 16 byte random nonce
        random_nonce = Random.get_random_bytes(16)

        # encrypt the session key with public key
        encrypted_symmentric_key = EncryptionUtils.rsa_encrypt(public_key_file_name=pubkeydirectory,
                                                               data=self._symmetrickey)

        # prepare data for signature
        data_for_sign = self._dirname + self._pubkey + base64.encodestring(encrypted_symmentric_key) + base64.encodestring(random_nonce)

        # get sha256
        data_for_sign_sha256 = EncryptionUtils.sha256(data=data_for_sign)

        # sign with private key

        FileUtils.write_data_to_file(filename="symmetricOut.txt", data=base64.encodestring(encrypted_symmentric_key))
        return

    def decrypt(self):
        FileUtils.walk_in_directory(directory=self._dirname, callback=self.decrypt_callback)
        return

from file_utils import FileUtils
from encryption_utils import EncryptionUtils
from Crypto import Random
import base64
import json
import os.path
import time


class InfoVault:
    def __init__(self, keydirectory, keyname, operation_directory, passphrase):
        """
        :param keydirectory: <keyname>_priv.pem <keyname>_pub.pem
        :param keyname
        :param dirname: directory which will be encrypted or decrypted
        :param passphrase
        """
        self._keydirectory = keydirectory
        self._keyname = keyname
        self._pubkeydirectory = os.path.join(self._keydirectory, self._keyname + "_pub.pem")
        self._privkeydirectory = os.path.join(self._keydirectory, self._keyname + "_priv.pem")
        self._operation_directory = operation_directory
        self._symmetrickey = ""
        self._passphrase = passphrase
        self._areParametersVerified = False

    def check_the_parameters(self):
        """
        As given with parameters check if given operation parameters
        and pub priv key pair files are exists.
        Passphrase of the given private key is also checked accordingly.
        :return: True or False
        """
        # first check if provided public & private keys are exists.
        if not os.path.isfile(path=self._pubkeydirectory):
            print("Public key file is not found under " + self._pubkeydirectory)
            return False

        # first check if provided public & private keys are exists.

        if not os.path.isfile(path=self._privkeydirectory):
            print("Public key file is not found under " + self._privkeydirectory)
            return False

        # check the operation directory
        if not os.path.isdir(self._operation_directory):
            print("Operation directory " + self._operation_directory + " has not been found")
            return False

        # check passphrase of private key
        isPassphraseValid = EncryptionUtils.check_rsa_priv_passphase(priv_key_file_name=self._privkeydirectory,
                                                                     passphrase=self._passphrase)
        if not isPassphraseValid:
            print("Given passphrase is invalid, for the private key " + self._privkeydirectory)
            return False

        # all is ok
        self._areParametersVerified = True
        print("All given parameters are valid!")
        return True

    def encrypt_callback(self, filename):
        print("Encryption of : \n" + filename)
        time1 = time.time()
        EncryptionUtils.file_encrypt(key=self._symmetrickey, file=filename)
        elapsed_time = (time.time() - time1) * 1000
        print ("Elapsed Time: " + str(elapsed_time))

        return

    def decrypt_callback(self, filename):
        print("Dencryption of : \n" + filename)
        time1 = time.time()
        EncryptionUtils.file_decrypt(key=self._symmetrickey, file=filename)
        elapsed_time = (time.time() - time1) * 1000
        print ("Elapsed Time: " + str(elapsed_time))
        return

    def encrypt(self):

        if not self._areParametersVerified:
            print("Verify the parameters first!")
            return

        # create 16 byte random nonce
        random_nonce = base64.encodestring(Random.get_random_bytes(16))

        # first create a 256 bit AES key
        key_size = 32  # bytes

        self._symmetrickey = Random.get_random_bytes(key_size)

        # encrypt the session key with public key
        encrypted_session_key = \
            EncryptionUtils.rsa_encrypt(public_key_file_name=self._pubkeydirectory,
                                        data=self._symmetrickey)

        # prepare data for signature
        data_for_sign = self._operation_directory + encrypted_session_key \
                        + random_nonce \
                        + self._keyname \

        # get sha256
        data_for_sign_sha256 = EncryptionUtils.sha256(data=data_for_sign).hexdigest()

        # sign with private key
        signature = EncryptionUtils.rsa_sign(private_key_file_name=self._privkeydirectory, data=data_for_sign_sha256,
                                             passphrase=self._passphrase)

        # generate and write the json
        configuration_json = {
            "operation_directory": self._operation_directory,
            "encrypted_session_key": encrypted_session_key,
            "random_nonce": random_nonce,
            "key_name": self._keyname,
            "signature": signature
        }

        configuration_json_str = json.dumps(configuration_json)

        configuration_file_name = os.path.relpath(self._operation_directory, ".") + ".InfoVault"
        FileUtils.write_data_to_file(filename=(self._operation_directory + "/../" + configuration_file_name),
                                     data=configuration_json_str)

        # encryption is performed via provided callback function
        FileUtils.walk_in_directory(directory=self._operation_directory, callback=self.encrypt_callback)

        return

    def decrypt(self):

        if not self._areParametersVerified:
            print("Verify the parameters first!")
            return

        #  findout the configuration file
        configuration_file_name = os.path.relpath(self._operation_directory, ".") + ".InfoVault"
        if not os.path.isfile(path=configuration_file_name):
            print("Configuration file  " + configuration_file_name + " does not exists")
            return

        FileVault_configuration_json = FileUtils.read_data_from_file(filename=configuration_file_name)

        # decode the json
        FileVault_configuration = json.loads(FileVault_configuration_json)

        # parse the json
        try:
            operation_directory = FileVault_configuration["operation_directory"]
            encrypted_session_key = FileVault_configuration["encrypted_session_key"]
            random_nonce = FileVault_configuration["random_nonce"]
            key_name = FileVault_configuration["key_name"]
            signature = FileVault_configuration["signature"]
        except Exception, e:
            print("Error occurred while processing configuration file, aborting..." + str(e))
            return

        # construct signature data
        data_for_verify = operation_directory + encrypted_session_key \
                                              + random_nonce \
                                              + key_name \

        hash_data_for_verify = EncryptionUtils.sha256(data=data_for_verify).hexdigest()

        # verify the signature
        verifyResult = EncryptionUtils.rsa_verify(public_key_file_name=self._pubkeydirectory,
                                                  data=hash_data_for_verify,
                                                  signature=signature)
        if not verifyResult:
            print("Signature verification is failed")
            return

        # decrypt the symmetric key
        self._symmetrickey = EncryptionUtils.rsa_decrypt(private_key_file_name=self._privkeydirectory,
                                                         cipher_base64=encrypted_session_key,
                                                         passphrase=self._passphrase)

        # decrypt the files
        FileUtils.walk_in_directory(directory=self._operation_directory, callback=self.decrypt_callback)

        # remove the configuration file
        os.remove(configuration_file_name)
        print("Decryption is finished")
        return

from encryption_utils import EncryptionUtils
from FileVault import FileVault
from Crypto import Random
import base64
import time


def enc_callback(filename):
    print("Callback is called with: \n" + filename)
    EncryptionUtils.file_encrypt(key="1234567890123456", file=filename)
    return


def dec_callback(filename):
    print("Callback is called with: \n" + filename)
    EncryptionUtils.file_decrypt(key="1234567890123456", file=filename)
    return


def rsa_sign_verify_test():
    signed_data_base64 = EncryptionUtils.rsa_sign(private_key_file_name="test_priv.pem", data="test123", passphrase="123")
    verify_result = EncryptionUtils.rsa_verify(public_key_file_name="test_pub.pem", data="test123", signature=signed_data_base64)
    if verify_result:
        print "Verified"
        return True
    else:
        print "Not verified"
        return False


def rsa_encrypt_decrypt_test():
    symmetric1 = Random.get_random_bytes(32)

    print("Symmetric 1 : " + symmetric1)
    encrypted_symmetric_key = \
        EncryptionUtils.rsa_encrypt(public_key_file_name="test_pub.pem",
                                    data=symmetric1)

    # decrypt the symmetric key
    symmetric2 = EncryptionUtils.rsa_decrypt(private_key_file_name="test_priv.pem",
                                             cipher_base64=encrypted_symmetric_key,
                                             passphrase="123")
    print("Symmetric 2 : " + symmetric1)
    if symmetric1 == symmetric2:
        return True
    return False


def print_main_menu():
    print("Please Select the action")
    print("1-Encrypt File or Directory")
    print("2-Decrypt File or Directory")
    print("3-Generate Key Pair")
    print("Press q for exit the program")


def main_function():
    print("############ APPLICATION FILE VAULT ############")

    while True:

        # print the main menu
        print_main_menu()

        # get user choice
        choice = 'x'
        if choice == 'q':
            break
        if not (1 <= int(choice) <= 3):
            print("Wrong input try again")
        else:
            # perform the required action...
            print "test"

if __name__ == "__main__":
    """print str(EncryptionUtils.check_rsa_priv_passphase(priv_key_file_name="test_priv.pem",
                                                       passphrase="13"))"""

    fileVault = FileVault(passphrase="123", keydirectory=".", keyname="test", operation_directory="./FilesToEncrypt")
    print fileVault.check_the_parameters()

    time1 = time.time()
    fileVault.encrypt()
    elapsedTime = (time.time() - time1)*1000
    print (elapsedTime)
    fileVault.decrypt()

    #print rsa_encrypt_decrypt_test()

    """fileVault = FileVault(dirname="./FilesToEncrypt", keyname="test", keydirectory=".")
    fileVault.encrypt()
    fileVault.decrypt()"""


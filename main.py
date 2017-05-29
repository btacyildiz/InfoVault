from encryption_utils import EncryptionUtils
from FileVault import InfoVault
from Crypto import Random
import time
import getpass
import sys
import os
import glob


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

def create_test_files():
    size = 1000  # initially 1MB  1, 10, 100, 1000, 10 000 000 000
    chunk = 1000
    while size <= 1000 * 1000 * 10:
        with open(name=("FilesToEncrypt/test" + str(size/1000))+".txt", mode="w") as openedfile:
            for i in range(0, size):
                openedfile.write("*" * chunk)
        print("File " + "test" + str(size/1000) + " created")
        size *= 10


def get_passphrase_from_user():
    while True:
        pass1 = getpass.getpass("Enter Passphrase: ")
        pass2 = getpass.getpass("Re-Enter Passphrase: ")
        if pass1 == pass2:
            return pass1
        else:
            print("Passphrases do not match.")
            return None


def get_key_name(keydir):
    print("Please specify key name under directory " + keydir)
    keyname = raw_input("Enter keyname: ")
    return keyname


def print_help():
    print("--help:  prints this information")
    print("-opdir:  operation directory for encryption and decryption")
    print("included files given directory will be encrypted/decrypted")
    print("-keydir: specified directory for searching related keys")
    print("Example usage:  <programname> -opdir ./FilesToEncrypt -keydir .")


def print_main_menu():
    print("Please Select the action")
    print("1-Encrypt Directory")
    print("2-Decrypt Directory")
    print("3-Generate Key Pair")
    print("4-Show Keys")
    print("Press q for exit the program")


def main_function(keydir, keyname, opdir = None):
    print("############ APPLICATION FILE VAULT ############")
    infoVault = None
    while True:

        # print the main menu
        print_main_menu()

        # get user choice
        choice = raw_input()
        if choice == 'q':
            break
        if not (1 <= int(choice) <= 3):
            print("Wrong input try again")
        else:
            if choice == "1" or choice == "2":
                passphrase = get_passphrase_from_user()
                infoVault = InfoVault(passphrase=passphrase, keyname=keyname, keydirectory=keydir,
                                      operation_directory=opdir)
                if infoVault.check_the_parameters():
                    if choice == "1":
                        infoVault.encrypt()
                    elif choice == "2":
                        infoVault.decrypt()
                else:
                    print("Parameters not good, aborting...")
                    return

            elif choice == "3":
                if os.path.isdir(keydir):
                    passphrase = get_passphrase_from_user()
                    if passphrase:
                        EncryptionUtils.rsa_generate(keypath=keydir, keyname=keyname, passphrase=passphrase)
                        print("Key pair has been generated. Under " + keydir + " named " + keyname)
                else:
                    print("Given key directory "+ keydir +" does not exists.")
            elif choice == "4":
                print glob.glob(os.path.join(keydir, keyname+"*.pem"))


if __name__ == "__main__":

    # get the parameters
    args = sys.argv
    keydir = ""
    opdir = ""
    print(len(args))
    print(args)
    if len(args) == 2 and args[1] == "--help":
        print_help()
    elif len(args) == 3 and args[1] == "-keydir":
        keydir = args[2]
    elif len(args) == 5 and (args[1] == "-opdir" and args[3] == "-keydir"):
        opdir = args[2]
        keydir = args[4]
    else:
        print("Insufficient parameters, aborting...")
        print_help()
        sys.exit()

    keyname = get_key_name(keydir)

    main_function(opdir=opdir, keydir=keydir, keyname= keyname)

    sys.exit()

    if 0:
        create_test_files()
    else:

        infoVault = InfoVault(passphrase="123", keydirectory=".", keyname="test", operation_directory="./FilesToEncrypt")
        print fileVault.check_the_parameters()

        time1 = time.time()
        fileVault.encrypt()
        elapsedTime = (time.time() - time1)*1000
        print("Total elapsed time: " + str(elapsedTime))
        infoVault.decrypt()
    #print rsa_encrypt_decrypt_test()


    """fileVault = FileVault(dirname="./FilesToEncrypt", keyname="test", keydirectory=".")
    fileVault.encrypt()
    fileVault.decrypt()"""


import encryption_utils
from file_utils import FileUtils
import os
import time


def enc_callback(filename):
    print("Callback is called with: \n" + filename)
    encryption_utils.file_encrypt(key="1234567890123456", file=filename)
    return


def dec_callback(filename):
    print("Callback is called with: \n" + filename)
    encryption_utils.file_decrypt(key="1234567890123456", file=filename)
    return

if __name__ == "__main__":
    print "####"
    start_time = time.time()
    FileUtils.walk_in_directory(directory="./FilesToEncrypt", callback=dec_callback)
    print("Elapsed time : " + str(time.time() - start_time))
    #encryption_utils.file_encrypt(filename="text.txt", outfilename="enc_text.txt", key="1234567890123456")
    #encryption_utils.file_decrypt(filename="enc_text.txt", outfilename="plain_text.txt", key="1234567890123459")
    #encryption_utils.generate_rsa_keys(filename="test")
    print("Main function is called")


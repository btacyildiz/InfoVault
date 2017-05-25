import encryption_utils


def enc_callback(filename):
    print("Callback is called with: \n" + filename)
    encryption_utils.file_encrypt(key="1234567890123456", file=filename)
    return


def dec_callback(filename):
    print("Callback is called with: \n" + filename)
    encryption_utils.file_decrypt(key="1234567890123456", file=filename)
    return


def rsa_sign_verify_test():
    signed_data_base64 = encryption_utils.rsa_sign(private_key_file_name="test_priv.pem", data="test123", passphrase="123")
    verify_result = encryption_utils.rsa_verify(public_key_file_name="test_pub.pem", data="test123", signature=signed_data_base64)
    if verify_result:
        print "Verified"
        return True
    else:
        print "Not verified"
        return False


def rsa_encrypt_decrypt_test():

    cipher_base64 = encryption_utils.rsa_encrypt("test_pub.pem", "test")

    plain_text = encryption_utils.rsa_decrypt(private_key_file_name="test_priv.pem", cipher_base64=cipher_base64, passphrase="123")

    if plain_text == "test":
        return True
    return False

if __name__ == "__main__":
    print "####"
    rsa_sign_verify_test()

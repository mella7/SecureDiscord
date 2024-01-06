from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_encrypt_alternative(message, receiver_public_key):
    message = str.encode(message)
    rsa_public_key = RSA.importKey(receiver_public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_message = rsa_public_key.encrypt(message)
    encrypted_message = base64.b64encode(encrypted_message)
    return encrypted_message

def rsa_decrypt_alternative(encrypted_message, receiver_private_key):
    rsa_private_key = RSA.importKey(receiver_private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = rsa_private_key.decrypt(encrypted_message)
    return decrypted_message

# FOR TESTING ALTERNATIVE FUNCTIONS
def rsa_encrypt_decrypt_alternative():
    # Generating RSA key pair
    key = RSA.generate(2048)
    # Extracting private_key
    private_key = key.export_key('PEM')
    # Extracting public_key
    public_key = key.publickey().exportKey('PEM')
    # Get the message to send
    message = input('\nPlease enter your message for RSA encryption and decryption: ')
    # Use the alternative functions for encryption and decryption
    encrypted_message = rsa_encrypt_alternative(message, public_key)
    decrypted_message = rsa_decrypt_alternative(encrypted_message, private_key)
    print('\nYour encrypted message is : ', encrypted_message)
    print('\nYour message after decryption is : ', decrypted_message)

# FOR TESTING ALTERNATIVE FUNCTIONS
# rsa_encrypt_decrypt_alternative()

# get rsa key from file
def get_rsa_key_alternative(filepath):
    with open(filepath, mode='rb') as private_file:
        priv_key_data = private_file.read()
        private_key = RSA.importKey(priv_key_data)
        return private_key







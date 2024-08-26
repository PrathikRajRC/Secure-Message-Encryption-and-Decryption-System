from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key(key_data, filename):
    with open(filename, 'wb') as file:
        file.write(key_data)

def load_key(filename):
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        return None

def rsa_encrypt(message, public_key_data):
    public_key = RSA.import_key(public_key_data)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

def rsa_decrypt(encrypted_message, private_key_data):
    private_key = RSA.import_key(private_key_data)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode('utf-8')

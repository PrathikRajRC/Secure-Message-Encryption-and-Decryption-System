import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_aes_key():
    
    return os.urandom(16).hex()[:16]

def aes_encrypt(plain_text, key):
    """Encrypt the plain_text using AES encryption with the provided key."""
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text.hex()

def aes_decrypt(encrypted_text, key):
    """Decrypt the encrypted_text using AES decryption with the provided key."""
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(bytes.fromhex(encrypted_text))
    return unpad(decrypted_padded_text, AES.block_size).decode('utf-8')


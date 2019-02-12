import os
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def saveFile(filename, content):
    fd = open(filename, 'wb')
    fd.write(content)
    fd.close()


def readFile(filename):
    fd = open(filename, 'rb')
    content = fd.read()
    fd.close()
    return content


def encrypt(plaintext, key, associated_data='', byts=False):

    # Generate a random 96-bit IV.
    iv = os.urandom(12)
    
    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    
    # associated_data will be authenticated but not encrypted, it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data.encode())

    # Encrypt the plaintext and get the associated ciphertext. GCM does not require padding.
    if byts:
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    else:
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    package = iv + encryptor.tag + ciphertext

    hmac = generate_mac(key, package)

    return hmac + package


def decrypt(package, key, associated_data='', byts=False):
    
    hmac = package[:32]

    macDest = generate_mac(key, package[32:])


    if (hmac != macDest):
        if byts:
            return b'ERROR - MAC is not equal'
        else:
            return 'ERROR - MAC is not equal'

    iv = package[32:44]

    tag = package[44:60]

    ciphertext = package[60:]


    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    # We put associated_data back in or the tag will fail to verify when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data.encode())

    # Decryption gets us the authenticated plaintext. If the tag does not match an InvalidTag exception will be raised.
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if byts:
        return plaintext
    else:
        return plaintext.decode()


def generate_mac(key, crypto):
    h = hmac.HMAC(key, hashes.SHA256(), backend = default_backend())

    h.update(crypto)

    return h.finalize()

def generate_key(passphraseB, salt=os.urandom(16)):
    backend = default_backend()

    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
    )

    key = kdf.derive(passphraseB)

    return key, salt
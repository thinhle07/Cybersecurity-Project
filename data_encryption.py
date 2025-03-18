from PIL import Image, ImageDraw, ImageFont
import os
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_phrase(algorithm, key, phrase):
    try:
        if algorithm == "N/A":
            return phrase
        phrase_bytes = phrase.encode()
        key = key.ljust(16)[:16]
        key_bytes = key.encode()
        if algorithm == "AES":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            padded_data = pad(phrase_bytes, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
        elif algorithm == "DES":
            key_bytes = key_bytes[:8]
            cipher = DES.new(key_bytes, AES.MODE_ECB)
            padded_data = pad(phrase_bytes, DES.block_size)
            encrypted = cipher.encrypt(padded_data)
        elif algorithm == "Blowfish":
            cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
            padded_data = pad(phrase_bytes, Blowfish.block_size)
            encrypted = cipher.encrypt(padded_data)
        else:
            return None
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Error encrypting phrase: {e}")
        return None

def decrypt_phrase(algorithm, key, encrypted_phrase):
    try:
        if algorithm == "N/A":
            return encrypted_phrase
        encrypted_bytes = base64.b64decode(encrypted_phrase)
        key = key.ljust(16)[:16]
        key_bytes = key.encode()
        if algorithm == "AES":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        elif algorithm == "DES":
            key_bytes = key_bytes[:8]
            cipher = DES.new(key_bytes, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), DES.block_size)
        elif algorithm == "Blowfish":
            cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), Blowfish.block_size)
        else:
            return None
        return decrypted.decode()
    except Exception as e:
        print(f"Error decrypting phrase: {e}")
        return None
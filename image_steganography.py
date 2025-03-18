from PIL import Image, ImageDraw, ImageFont
import os
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_data(algorithm, key, data):
    if algorithm == "N/A":
        return data
    data_bytes = data.encode()
    key = key.ljust(16)[:16]
    key_bytes = key.encode()
    if algorithm == "AES":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        padded_data = pad(data_bytes, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
    elif algorithm == "DES":
        key_bytes = key_bytes[:8]
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        padded_data = pad(data_bytes, DES.block_size)
        encrypted = cipher.encrypt(padded_data)
    elif algorithm == "Blowfish":
        cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
        padded_data = pad(data_bytes, Blowfish.block_size)
        encrypted = cipher.encrypt(padded_data)
    else:
        return None
    return base64.b64encode(encrypted).decode()

def encode_image(image_path, secret_data, key, algorithm, output_image_path):
    try:
        encrypted_data = encrypt_data(algorithm, key, secret_data) + "###END###"
        data_bin = ''.join(format(ord(c), '08b') for c in encrypted_data)
        image = Image.open(image_path)
        encoded_image = image.copy()
        pixel_data = encoded_image.load()
        data_index = 0
        for y in range(encoded_image.height):
            for x in range(encoded_image.width):
                r, g, b = pixel_data[x, y]
                if data_index < len(data_bin):
                    r = (r & 0xFE) | int(data_bin[data_index])
                    data_index += 1
                if data_index < len(data_bin):
                    g = (g & 0xFE) | int(data_bin[data_index])
                    data_index += 1
                if data_index < len(data_bin):
                    b = (b & 0xFE) | int(data_bin[data_index])
                    data_index += 1
                pixel_data[x, y] = (r, g, b)
                if data_index >= len(data_bin):
                    break
        encoded_image.save(output_image_path)
        return True
    except Exception as e:
        print(f"Error encoding image: {e}")
        return False

def decrypt_data(algorithm, key, data):
    if algorithm == "N/A":
        return data
    data_bytes = base64.b64decode(data)
    key = key.ljust(16)[:16]
    key_bytes = key.encode()
    if algorithm == "AES":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(data_bytes), AES.block_size)
    elif algorithm == "DES":
        key_bytes = key_bytes[:8]
        cipher = DES.new(key_bytes, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(data_bytes), DES.block_size)
    elif algorithm == "Blowfish":
        cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
        decrypted = unpad(cipher.decrypt(data_bytes), Blowfish.block_size)
    else:
        return None
    return decrypted.decode()

def extract_data_from_image(encoded_image_path):
    try:
        encoded_image = Image.open(encoded_image_path)
        pixel_data = encoded_image.load()
        data_bin = ''
        for y in range(encoded_image.height):
            for x in range(encoded_image.width):
                r, g, b = pixel_data[x, y]
                data_bin += str(r & 1) + str(g & 1) + str(b & 1)
        extracted_data = ''
        for i in range(0, len(data_bin), 8):
            byte = data_bin[i:i+8]
            if len(byte) < 8:
                break
            extracted_data += chr(int(byte, 2))
        return extracted_data.split("###END###")[0]
    except Exception as e:
        print(f"Error extracting data: {e}")
        return None
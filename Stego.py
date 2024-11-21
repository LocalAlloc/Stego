from PIL import Image
import binascii
import optparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from cryptography.hazmat.primitives import hashes

# Function to hash AES key using SHA-256
def hash_with_sha256(data):
    """
    Hash the provided data using SHA-256.
    :param data: Data to hash (bytes)
    :return: SHA-256 hash (bytes)
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

# AES encryption/decryption functions
def encrypt_message(key, message):
    # Hash the key using SHA-256
    key = hash_with_sha256(key)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, encrypted_message):
    # Hash the key using SHA-256
    key = hash_with_sha256(key)
    
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# Steganography functions
def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)

def hex2rgb(hexcode):
    return tuple(int(hexcode[i:i+2], 16) for i in (1, 3, 5))

def str2bin(message):
    binary = bin(int(binascii.hexlify(message), 16))[2:]
    return binary.zfill(8 * ((len(binary) + 7) // 8))

def bin2str(binary):
    if len(binary) % 8 != 0:
        binary = '0' + binary  # Pad with a leading zero if length is odd

    # Convert the padded binary string to hexadecimal
    hex_data = hex(int(binary, 2))[2:]  # Strip off '0x' prefix
    # If the hex_data has an odd number of characters, pad with '0' at the beginning
    if len(hex_data) % 2 != 0:
        hex_data = '0' + hex_data
    
    # Now, unhexlify the hex string into a byte string (the actual message)
    message = binascii.unhexlify(hex_data)
    
    return message

def encode(hexcode, digit):
    if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
        return hexcode[:-1] + digit
    else:
        return None

def decode(hexcode):
    if hexcode[-1] in ('0', '1'):
        return hexcode[-1]
    else:
        return None

def hide(filename, message, key):
    img = Image.open(filename)
    binary = str2bin(encrypt_message(key, message)) + '1111111111111110'
    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        datas = img.getdata()
        newData = []
        digit = 0

        for item in datas:
            if digit < len(binary):
                newpix = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
                if newpix is None:
                    newData.append(item)
                else:
                    r, g, b = hex2rgb(newpix)
                    newData.append((r, g, b, 255))
                    digit += 1
            else:
                newData.append(item)
        img.putdata(newData)
        img.save(filename, "PNG")
        return "Completed!"
    return "Incorrect Image Mode!"

def retrieve(filename, key):
    img = Image.open(filename)
    binary = ''
    
    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        datas = img.getdata()

        for item in datas:
            digit = decode(rgb2hex(item[0], item[1], item[2]))
            if digit is None:
                pass
            else:
                binary += digit
                if binary[-16:] == "1111111111111110":
                    encrypted_message = bin2str(binary[:-16])
                    return decrypt_message(key, encrypted_message)
    return "Incorrect Image Mode!"



def Main():
    parser = optparse.OptionParser('Usage: %prog -e/d <target file> -k <AES Key>')
    parser.add_option('-e', dest='hide', type="string", help="Target picture path to hide text")
    parser.add_option('-d', dest='retrieve', type="string", help="Target picture path to retrieve text")
    parser.add_option('-k', dest='AES_key', type="string", help="Enter the Base64-encoded AES Key.")
    (options, args) = parser.parse_args()

    if not options.AES_key:
        print("Error: AES key is required. Use the -k option to provide it.")
        exit(0)

    try:
        # Decode the Base64-encoded AES key
        key = base64.b64decode(options.AES_key)
        if len(key) not in (16, 24, 32):
            raise ValueError("Invalid AES key length. It must be 16, 24, or 32 bytes.")
    except Exception as e:
        print(f"Error: Invalid AES Key provided. {e}")
        exit(0)

    if options.hide:
        text = input('Enter message: ')
        print(hide(options.hide, text, key))
    elif options.retrieve:
        print(retrieve(options.retrieve, key))
    else:
        print(parser.usage)
        exit(0)

if __name__ == "__main__":
    Main()

import hashlib
import os
import base64
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD4, HMAC, SHA1, SHA256
from Crypto.Random import get_random_bytes
from fuzzywuzzy import process

aes_options = {
    "AES-128": 16,
    "AES-192": 24,
    "AES-256": 32,
    "AES-512": 64,  # Custom addition, not a standard AES key size
}

rsa_key_sizes = {
    "RSA-1024": 1024,
    "RSA-2048": 2048,
    "RSA-4096": 4096
}

# Define hash functions and modes
hash_functions = {
    "SHA-512": hashlib.sha512,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-224": hashlib.sha224,
    "SHA-512/224": lambda data: hashlib.sha512(data).digest()[:28],
    "SHA-512/256": lambda data: hashlib.sha512(data).digest()[32:64],
    "MD5": hashlib.md5,
    "MD4": lambda data: MD4.new(data).hexdigest(),
    "SHA3-224": hashlib.sha3_224,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
    "BLAKE2s": hashlib.blake2s,
    "BLAKE2b": hashlib.blake2b,
    "SHAKE128": lambda data, length: hashlib.shake_128(data).digest(length),
    "SHAKE256": lambda data, length: hashlib.shake_256(data).digest(length),
    "cSHAKE128": lambda data, length, customization: hashlib.shake_128(data + customization.encode()).digest(length),
    "cSHAKE256": lambda data, length, customization: hashlib.shake_256(data + customization.encode()).digest(length),
    "KMAC128": lambda data, key, customization: hashlib.new('sha3_128', data + customization.encode(), key).digest(),
    "KMAC256": lambda data, key, customization: hashlib.new('sha3_256', data + customization.encode(), key).digest(),
    "Poly1305": lambda data, key: hashlib.new('sha256', data + key).digest()[:16],
}

hashcat_modes = {
    "SHA-512": "1700",
    "SHA-256": "1400",
    "SHA-384": "10800",
    "SHA-224": "1300",
    "SHA-512/224": "20400",
    "SHA-512/256": "20500",
    "MD5": "0",
    "MD4": "900",
    "SHA1": "100",
    "SHA3-224": "17300",
    "SHA3-256": "17400",
    "SHA3-384": "17500",
    "SHA3-512": "17600",
    "BLAKE2b": "600",
    "GOST R 34.11-2012 256-bit": "11700",
    "GOST R 34.11-2012 512-bit": "11800",
    "GOST R 34.11-94": "6900",
    "GPG": "17010",
    "Half MD5": "5100",
    "Keccak-224": "17700",
    "Keccak-256": "17800",
    "Keccak-384": "17900",
    "Keccak-512": "18000",
    "Whirlpool": "6100",
    "SipHash": "10100",
    "HMAC-MD5": "50",
    "HMAC-SHA1": "150",
    "HMAC-SHA256": "1450",
    "HMAC-SHA512": "1750",
    "PBKDF2-HMAC-MD5": "11900",
    "PBKDF2-HMAC-SHA1": "12000",
    "PBKDF2-HMAC-SHA256": "10900",
    "PBKDF2-HMAC-SHA512": "12100",
    "scrypt": "8900",
    "phpass": "400",
    "TACACS+": "16100",
    "SIP digest authentication (MD5)": "11400",
    "IKE-PSK MD5": "5300",
    "IKE-PSK SHA1": "5400",
    "SNMPv3 HMAC-MD5-96": "25100",
    "SNMPv3 HMAC-SHA1-96": "25200",
    "SNMPv3 HMAC-SHA224-128": "26700",
    "SNMPv3 HMAC-SHA256-192": "26800",
    "SNMPv3 HMAC-SHA384-256": "26900",
    "SNMPv3 HMAC-SHA512-384": "27300",
    "WPA-EAPOL-PBKDF2": "2500",
    "WPA-EAPOL-PMK": "2501",
    "WPA-PBKDF2-PMKID+EAPOL": "22000",
    "WPA-PMK-PMKID+EAPOL": "22001",
}

def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded_data):
    return base64.b64decode(encoded_data)

def aes_encrypt_ecb(plaintext, key):
    key_hashed = hashlib.sha256(key).digest()[:16]  # Adjust size for 128-bit key
    cipher = AES.new(key_hashed, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_decrypt_ecb(ciphertext, key):
    key_hashed = hashlib.sha256(key).digest()[:16]  # Adjust size for 128-bit key
    cipher = AES.new(key_hashed, AES.MODE_ECB)
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    return decrypted_plaintext

def aes_encrypt(plaintext, key, iv=None):
    try:
        key_hashed = hashlib.sha256(key).digest()
        if iv is None:
            iv = os.urandom(16)
        cipher = AES.new(key_hashed, AES.MODE_CBC, iv)
        padded_plaintext = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext, iv
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None, None

def aes_decrypt(ciphertext, key, iv):
    try:
        key_hashed = hashlib.sha256(key).digest()
        cipher = AES.new(key_hashed, AES.MODE_CBC, iv)
        decrypted_padded_plaintext = cipher.decrypt(ciphertext)
        decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
        return decrypted_plaintext
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def rsa_generate_key_pair(key_size):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    try:
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    except (ValueError, TypeError) as e:
        print(f"Error encrypting data: {e}")
        return None

def rsa_decrypt(ciphertext, private_key):
    try:
        private_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except (ValueError, TypeError) as e:
        print(f"Error decrypting data: {e}")
        return None

def hash_string(hash_type):
    d = input(f"Enter a string to hash with {hash_type}: ")
    if hash_type in hash_functions:
        if hash_type in ["SHAKE128", "SHAKE256"]:
            length = int(input("Enter output length (bytes): "))
            hashed_value = hash_functions[hash_type](d.encode('utf-8'), length)
        elif hash_type in ["cSHAKE128", "cSHAKE256"]:
            customization = input("Enter customization string: ")
            length = int(input("Enter output length (bytes): "))
            hashed_value = hash_functions[hash_type](d.encode('utf-8'), length, customization)
        elif hash_type in ["KMAC128", "KMAC256"]:
            key = os.urandom(16)
            customization = input("Enter customization string: ")
            hashed_value = hash_functions[hash_type](d.encode('utf-8'), key, customization)
        elif hash_type == "Poly1305":
            key = os.urandom(32)
            hashed_value = hash_functions[hash_type](d.encode('utf-8'), key)
        else:
            hashed_value = hash_functions[hash_type](d.encode('utf-8')).digest()
        print(f"Hashed value: {hashed_value.hex()}")
    else:
        print("Hash function not found")

def hash_cracking(hash_value, hash_type, hashcat_path):
    if hash_type in hashcat_modes:
        mode = hashcat_modes[hash_type]
        try:
            subprocess.run([hashcat_path, '-m', mode, '-a', '0', hash_value, '--force'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Hashcat error: {str(e)}")
    else:
        print("Hash type not supported for cracking")

def select_aes_type():
    print("Available AES types:")
    for option in aes_options.keys():
        print(f"  {option}")
    selected_option = input("Enter your choice: ")
    return aes_options.get(selected_option, None)

def select_rsa_key_size():
    print("Available RSA key sizes:")
    for option in rsa_key_sizes.keys():
        print(f"  {option}")
    selected_option = input("Enter your choice: ")
    return rsa_key_sizes.get(selected_option, None)

def main():
    while True:
        print("Options:")
        print("1. Hash a string")
        print("2. Crack a hash")
        print("3. Encrypt AES")
        print("4. Decrypt AES")
        print("5. Encrypt RSA")
        print("6. Decrypt RSA")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("Available hash functions:")
            for func in hash_functions.keys():
                print(f"  {func}")
            hash_type = input("Enter hash function: ")
            hash_string(hash_type)
        elif choice == '2':
            hash_value = input("Enter hash value to crack: ")
            hash_type = input("Enter hash type: ")
            hashcat_path = input("Enter the path to hashcat: ")
            hash_cracking(hash_value, hash_type, hashcat_path)
        elif choice == '3':
            aes_type = select_aes_type()
            if aes_type:
                key = get_random_bytes(aes_type)
                plaintext = input("Enter plaintext: ").encode('utf-8')
                ciphertext, iv = aes_encrypt(plaintext, key)
                if ciphertext:
                    print(f"Encrypted ciphertext (base64): {encode_base64(ciphertext)}")
                    print(f"IV (base64): {encode_base64(iv)}")
            else:
                print("Invalid AES type selected")
        elif choice == '4':
            aes_type = select_aes_type()
            if aes_type:
                key = get_random_bytes(aes_type)
                iv = decode_base64(input("Enter IV (base64): "))
                ciphertext = decode_base64(input("Enter ciphertext (base64): "))
                plaintext = aes_decrypt(ciphertext, key, iv)
                if plaintext:
                    print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
            else:
                print("Invalid AES type selected")
        elif choice == '5':
            rsa_key_size = select_rsa_key_size()
            if rsa_key_size:
                private_key, public_key = rsa_generate_key_pair(rsa_key_size)
                print(f"Public Key: {encode_base64(public_key)}")
                print(f"Private Key: {encode_base64(private_key)}")
                plaintext = input("Enter plaintext to encrypt: ").encode('utf-8')
                ciphertext = rsa_encrypt(plaintext, public_key)
                if ciphertext:
                    print(f"Encrypted ciphertext (base64): {encode_base64(ciphertext)}")
            else:
                print("Invalid RSA key size selected")
        elif choice == '6':
            private_key = decode_base64(input("Enter private key (base64): "))
            ciphertext = decode_base64(input("Enter ciphertext (base64): "))
            plaintext = rsa_decrypt(ciphertext, private_key)
            if plaintext:
                print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
        elif choice == '7':
            break
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()

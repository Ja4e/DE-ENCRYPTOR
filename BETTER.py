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

# Define AES options and RSA key sizes
aes_options = {
    1: ("AES-128", 16),
    2: ("AES-192", 24),
    3: ("AES-256", 32),
}

rsa_key_sizes = {
    1: ("RSA-1024", 1024),
    2: ("RSA-2048", 2048),
    3: ("RSA-4096", 4096),
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
    try:
        # Add padding if necessary
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        return base64.b64decode(encoded_data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
        return None

def aes_encrypt(plaintext, key=None, mode='CBC', iv=None):
    try:
        if key is None:
            key_size = 16  # Default to AES-128
            key = get_random_bytes(key_size)
        else:
            key_size = len(key)
            key = hashlib.sha256(key).digest()[:key_size]  # Ensure key is the correct length

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            return ciphertext, None
        elif mode == 'CBC':
            if iv is None:
                iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            return ciphertext, iv
        else:
            raise ValueError("Invalid AES mode selected")
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None, None

def aes_decrypt(ciphertext, key=None, iv=None, mode='CBC'):
    try:
        if key is None:
            key = input("Enter AES key (base64): ")
            key = decode_base64(key)

        if key is None:
            raise ValueError("Key must be provided for decryption")

        key_size = len(key)
        key = hashlib.sha256(key).digest()[:key_size]  # Ensure key is the correct length

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_padded_plaintext = cipher.decrypt(ciphertext)
            decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
            return decrypted_plaintext
        elif mode == 'CBC':
            if iv is None:
                raise ValueError("IV must be provided for CBC mode")
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded_plaintext = cipher.decrypt(ciphertext)
            decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
            return decrypted_plaintext
        else:
            raise ValueError("Invalid AES mode selected")
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def rsa_generate_key_pair(key_size):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Save keys to PEM files
    with open('private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key)
    
    with open('public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key)
    
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

def hash_data(data, hash_algo):
    try:
        if hash_algo in hash_functions:
            hasher = hash_functions[hash_algo]()
            hasher.update(data)
            return hasher.digest()
        else:
            print(f"Unsupported hash algorithm: {hash_algo}")
            return None
    except Exception as e:
        print(f"Hashing error: {e}")
        return None

def hmac_data(data, key, hash_algo):
    try:
        if hash_algo in hash_functions:
            hasher = hash_functions[hash_algo]()
            hmac_obj = HMAC.new(key, msg=data, digestmod=hasher)
            return hmac_obj.digest()
        else:
            print(f"Unsupported hash algorithm: {hash_algo}")
            return None
    except Exception as e:
        print(f"HMAC error: {e}")
        return None

def crack_hash(hash_value, hash_algo, wordlist_file):
    try:
        with open(wordlist_file, 'r') as file:
            for line in file:
                word = line.strip().encode()
                hashed_word = hash_data(word, hash_algo)
                if hashed_word and hashed_word.hex() == hash_value:
                    return word.decode()
    except Exception as e:
        print(f"Hash cracking error: {e}")
        return None

def select_aes_key_size():
    print("Select AES key size:")
    for key, (name, _) in aes_options.items():
        print(f"{key}. {name}")
    choice = input("Enter choice: ")
    try:
        return aes_options[int(choice)]
    except (ValueError, KeyError):
        return None

def select_aes_mode():
    print("Select AES mode:")
    print("1. ECB")
    print("2. CBC")
    choice = input("Enter choice: ")
    return 'ECB' if choice == '1' else 'CBC' if choice == '2' else None

def select_rsa_key_size():
    print("Select RSA key size:")
    for key, (name, _) in rsa_key_sizes.items():
        print(f"{key}. {name}")
    choice = input("Enter choice: ")
    try:
        return rsa_key_sizes[int(choice)]
    except (ValueError, KeyError):
        return None

def main():
    while True:
        print("\nOptions:")
        print("1. Hash a string")
        print("2. Crack a hash")
        print("3. Encrypt AES")
        print("4. Decrypt AES")
        print("5. Encrypt RSA")
        print("6. Decrypt RSA")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            hash_string()
        elif choice == '2':
            hash_cracking()
        elif choice == '3':
            aes_type = select_aes_key_size()
            aes_mode = select_aes_mode()
            if aes_type and aes_mode:
                key_size = aes_type[1]
                key = get_random_bytes(key_size)
                plaintext = input("Enter plaintext: ").encode('utf-8')
                ciphertext, iv = aes_encrypt(plaintext, key, mode=aes_mode)
                if ciphertext:
                    print(f"Encrypted ciphertext (base64): {encode_base64(ciphertext)}")
                    if iv:
                        print(f"IV (base64): {encode_base64(iv)}")
                    print(f"Key (base64): {encode_base64(key)}")
            else:
                print("Invalid AES key size or mode selected")
        elif choice == '4':
            aes_type = select_aes_key_size()
            aes_mode = select_aes_mode()
            if aes_type and aes_mode:
                key_size = aes_type[1]
                key = input("Enter AES key (base64): ")
                key = decode_base64(key)
                iv = decode_base64(input("Enter IV (base64): ")) if aes_mode == 'CBC' else None
                ciphertext = decode_base64(input("Enter ciphertext (base64): "))
                plaintext = aes_decrypt(ciphertext, key, iv=iv, mode=aes_mode)
                if plaintext:
                    print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
            else:
                print("Invalid AES key size or mode selected")
        elif choice == '5':
            rsa_key_size = select_rsa_key_size()
            if rsa_key_size:
                private_key, public_key = rsa_generate_key_pair(rsa_key_size[1])
                print(f"Public Key saved to 'public_key.pem'")
                print(f"Private Key saved to 'private_key.pem'")
                plaintext = input("Enter plaintext to encrypt: ").encode('utf-8')
                ciphertext = rsa_encrypt(plaintext, public_key)
                if ciphertext:
                    print(f"Encrypted ciphertext (base64): {encode_base64(ciphertext)}")
            else:
                print("Invalid RSA key size selected")
        elif choice == '6':
            private_key_path = input("Enter the path to the private key file (PEM): ")
            try:
                with open(private_key_path, 'rb') as key_file:
                    private_key = key_file.read()
                ciphertext = decode_base64(input("Enter ciphertext (base64): "))
                plaintext = rsa_decrypt(ciphertext, private_key)
                if plaintext:
                    print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
            except FileNotFoundError:
                print("Private key file not found.")
            except Exception as e:
                print(f"Error reading private key or decrypting data: {e}")
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print("\nProgram interrupted. Exiting...")
            break

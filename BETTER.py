import hashlib
import os
import base64
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD4, HMAC, SHA1, SHA256
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
    "RSA-4096": 4096,
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

def rsa_generate_key_pair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


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
            hashed_value = hash_functions[hash_type](d.encode('utf-8')).hexdigest()

        base64_encode = input("Do you want to encode the hash in Base64? (yes/no): ").strip().lower()
        if base64_encode in ("yes", "y"):
            hashed_value = encode_base64(hashed_value.encode('utf-8'))

        print(f"{hash_type} Hash:", hashed_value)
    else:
        print("Unsupported hash type.")

# AES encryption
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

# AES decryption
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



def crack_hash():
    hash_type = choose_hash_type()
    if not hash_type:
        return

    hash_mode = hashcat_modes.get(hash_type)
    if not hash_mode:
        print("Hash mode not defined for this hash type.")
        return

    use_file = input(f"Is the {hash_type} hash in a file? (yes/no): ").strip().lower()

    if use_file in ("yes", "y"):
        file_path = input(f"Enter the path to the file containing the {hash_type} hash: ").strip()
        if not os.path.isfile(file_path):
            print("File does not exist. Please check the path and try again.")
            return
        with open(file_path, "r") as f:
            hash_to_crack = f.read().strip()
            base64_decode = input("Do you need to decode this hash from Base64? (yes/no): ").strip().lower()
            if base64_decode in ("yes", "y"):
                hash_to_crack = decode_base64(hash_to_crack)
    else:
        hash_to_crack = input(f"Enter the {hash_type} hash you want to crack: ").strip()
        base64_decode = input("Do you need to decode this hash from Base64? (yes/no): ").strip().lower()
        if base64_decode in ("yes", "y"):
            hash_to_crack = decode_base64(hash_to_crack)

    wordlist_path = input("Enter the path to your wordlist file (leave blank for brute-force): ").strip() or None
    hash_file = "hash_to_crack.txt"
    with open(hash_file, "w") as f:
        f.write(hash_to_crack)

    if wordlist_path:
        cmd = ['hashcat', '-m', hash_mode, hash_file, wordlist_path]
    else:
        cmd = ['hashcat', '-m', hash_mode, hash_file]

    subprocess.run(cmd)

def choose_hash_type():
    print("Available hash types:")
    for idx, hash_type in enumerate(hash_functions.keys(), start=1):
        print(f"{idx}. {hash_type}")

    try:
        choice = int(input("Choose a hash type by number: ").strip())
        if 1 <= choice <= len(hash_functions):
            hash_type = list(hash_functions.keys())[choice - 1]
            return hash_type
        else:
            print("Invalid number. Please choose a valid number from the list.")
            return None
    except ValueError:
        print("Invalid input. Please enter a number.")
        return None

def choose_aes_type():
    print("Available AES types:")
    for idx, aes_type in enumerate(aes_options.keys(), start=1):
        print(f"{idx}. {aes_type}")

    choice = input("Choose an AES type by name or number: ").strip()
    if choice.isdigit():
        choice = int(choice)
        if 1 <= choice <= len(aes_options):
            aes_type = list(aes_options.keys())[choice - 1]
            print(f"Selected AES type: {aes_type}")
            return aes_options[aes_type]
    else:
        best_match = process.extractOne(choice, aes_options.keys())
        if best_match[1] > 80:
            aes_type = best_match[0]
            print(f"Selected AES type: {aes_type}")
            return aes_options[aes_type]

    print("Invalid choice. Please choose a valid AES type.")
    return None


def choose_rsa_key_size():
    print("Available RSA key sizes:")
    for idx, rsa_size in enumerate(rsa_key_sizes.keys(), start=1):
        print(f"{idx}. {rsa_size}")

    choice = input("Choose an RSA key size by name or number: ").strip()
    best_match = process.extractOne(choice, rsa_key_sizes.keys())
    
    if best_match[1] > 80:
        rsa_key_size = best_match[0]
        print(f"Selected RSA key size: {rsa_key_size}")
        return rsa_key_sizes[rsa_key_size]
    else:
        print("Invalid choice. Please choose a valid RSA key size.")
        return None

def main():
    print("Welcome to the Cryptographic Tool")
    print("1. Hash a string")
    print("2. Crack a hash")
    print("3. AES Encryption/Decryption")
    print("4. RSA Encryption/Decryption")
    choice = input("Enter your choice (1, 2, 3, or 4): ").strip()

    if choice == '1':
        hash_type = choose_hash_type()
        if hash_type:
            hash_string(hash_type)
        else:
            print("Invalid hash type selected.")
    elif choice == '2':
        crack_hash()
    elif choice == '3':
        print("AES Encryption/Decryption")
        aes_choice = input("1. Encrypt\n2. Decrypt\nEnter your choice (1 or 2): ")
        if aes_choice == "1":
            aes_type = choose_aes_type()
            if aes_type:
                plaintext_input = input("Enter the plaintext you want to encrypt: ").encode('utf-8')
                key_input = input("Enter the encryption key (it will be hashed): ").encode('utf-8')
                key_hashed_hex = hashlib.sha256(key_input).digest().hex()
                print(f"Hashed Key (Hex): {key_hashed_hex}")

                generate_iv = input("Do you want to generate a random IV? (yes/no): ").strip().lower()
                if generate_iv == "no":
                    iv_input = bytes.fromhex(input("Enter your IV (in hexadecimal): "))
                else:
                    iv_input = None

                encrypted_ciphertext, iv = aes_encrypt(plaintext_input, key_input, iv_input)
                if encrypted_ciphertext and iv:
                    cipher_text_hex = encrypted_ciphertext.hex()
                    iv_hex = iv.hex()
                    print(f"Cipher Text (Hex): {cipher_text_hex}")
                    print(f"IV (Hex): {iv_hex}")
                else:
                    print("Encryption failed.")
            else:
                print("Invalid AES type selected.")
        elif aes_choice == "2":
            encrypted_ciphertext = bytes.fromhex(input("Enter the ciphertext (in hexadecimal): "))
            iv = bytes.fromhex(input("Enter the IV (in hexadecimal): "))
            key_input = input("Enter the decryption key (it will be hashed): ").encode('utf-8')

            decrypted_plaintext = aes_decrypt(encrypted_ciphertext, key_input, iv)
            if decrypted_plaintext:
                print(f"Decrypted Plaintext: {decrypted_plaintext.decode('utf-8')}")
            else:
                print("Decryption failed.")
        else:
            print("Invalid choice. Please select 1 or 2.")
    elif choice == "4":
        print("RSA Encryption/Decryption")
        rsa_choice = input("1. Generate Key Pair\n2. Encrypt\n3. Decrypt\nEnter your choice (1, 2 or 3): ")
        if rsa_choice == "1":
            rsa_key_size = choose_rsa_key_size()
            if rsa_key_size:
                private_key, public_key = rsa_generate_key_pair(key_size=rsa_key_size)
                with open("private_key.pem", "wb") as f:
                    f.write(private_key)
                with open("public_key.pem", "wb") as f:
                    f.write(public_key)
                print("RSA Key Pair generated and saved as 'private_key.pem' and 'public_key.pem'.")
            else:
                print("Invalid RSA key size selected.")
        elif rsa_choice == "2":
            plaintext_input = input("Enter the plaintext you want to encrypt: ").encode('utf-8')
            with open("public_key.pem", "rb") as f:
                public_key = f.read()
            encrypted_ciphertext = rsa_encrypt(plaintext_input, public_key)
            print(f"Encrypted Ciphertext (Base64): {encode_base64(encrypted_ciphertext)}")
        elif rsa_choice == "3":
            encrypted_ciphertext = decode_base64(input("Enter the encrypted ciphertext (Base64): "))
            with open("private_key.pem", "rb") as f:
                private_key = f.read()
            decrypted_plaintext = rsa_decrypt(encrypted_ciphertext, private_key)
            print(f"Decrypted Plaintext: {decrypted_plaintext.decode('utf-8')}")
        else:
            print("Invalid choice. Please select 1, 2, or 3.")
    else:
        print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print("\nProgram interrupted. Exiting...")
            break

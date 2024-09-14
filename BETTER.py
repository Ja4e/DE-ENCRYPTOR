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

def hash_string(hash_type):
    source_type = input("Hash text or file content? (text/file): ").strip().lower()
    
    if source_type in ("file","2"):
        file_path = input("Enter the path to the file: ").strip()
        if not os.path.isfile(file_path):
            print("File does not exist. Please check the path and try again.")
            return
        with open(file_path, "rb") as file:
            data = file.read()
    elif source_type in ("text","1"):
        data = input(f"Enter a string to hash with {hash_type}: ").encode('utf-8')
    else:
        print("Invalid choice.")
        return

    if hash_type in hash_functions:
        if hash_type in ["SHAKE128", "SHAKE256"]:
            length = int(input("Enter output length (bytes): "))
            hashed_value = hash_functions[hash_type](data, length)
        elif hash_type in ["cSHAKE128", "cSHAKE256"]:
            customization = input("Enter customization string: ")
            length = int(input("Enter output length (bytes): "))
            hashed_value = hash_functions[hash_type](data, length, customization)
        elif hash_type in ["KMAC128", "KMAC256"]:
            key = os.urandom(16)
            customization = input("Enter customization string: ")
            hashed_value = hash_functions[hash_type](data, key, customization)
        elif hash_type == "Poly1305":
            key = os.urandom(32)
            hashed_value = hash_functions[hash_type](data, key)
        else:
            hashed_value = hash_functions[hash_type](data).hexdigest()

        base64_encode = input("Do you want to encode the hash in Base64? (yes/no): ").strip().lower()
        if base64_encode in ("yes", "y"):
            hashed_value = encode_base64(hashed_value.encode('utf-8'))

        print(f"{hash_type} Hash:", hashed_value)
    else:
        print("Unsupported hash type.")


def hash_cracking():
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

    wordlist_path = input("Enter the path to your wordlist file (leave blank for brute-force): ").strip()
    hash_file = "hash_to_crack.txt"
    with open(hash_file, "w") as f:
        f.write(hash_to_crack + "\n")

    try:
        if not wordlist_path:
            print("No wordlist provided. Switching to combinatorial attack...")
            no_symbols = input("No symbols (yes/no)?: ").strip().lower()
            if no_symbols in ("yes", "y"):
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-1', '?l?u?d', '-i', '?1?1?1?1?1?1?1?1']
            else:
                print("WARNING! It will take a long time to crack if the hash is complex or long. Long passwords increase cracking time exponentially.")
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-i', '?a?a?a?a?a?a?a?a']
        else:
            if not os.path.isfile(wordlist_path):
                print("Wordlist file does not exist. Please check the path and try again.")
                return
            command = ['hashcat', '-m', hash_mode, hash_file, wordlist_path, '--force']
            print(f"Dictionary attack command: {' '.join(command)}")

        subprocess.run(command)
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
    finally:
        os.remove(hash_file)


def choose_hash_type():
    print("Available hash types:")
    for i, hash_type in enumerate(hash_functions.keys(), 1):
        print(f"{i}: {hash_type}")

    choice = int(input("Choose a hash type by number: "))
    if 1 <= choice <= len(hash_functions):
        return list(hash_functions.keys())[choice - 1]
    else:
        print("Invalid choice.")
        return None

def aes_encrypt_decrypt(operation):
    key_size = int(input("Choose AES key size (1: 128-bit, 2: 192-bit, 3: 256-bit): "))
    if key_size not in aes_options:
        print("Invalid key size.")
        return

    key_size_bytes = aes_options[key_size][1]
    key = input(f"Enter the AES key ({key_size_bytes * 8}-bit): ").encode()
    if len(key) < key_size_bytes:
        key = key.ljust(key_size_bytes, b'\0')

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key[:key_size_bytes], AES.MODE_CBC, iv)

    if operation in ("encrypt","1"):
        plaintext = input("Enter plaintext to encrypt: ").encode()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        print("Encrypted text (base64):", encode_base64(iv + ciphertext))
    elif operation in ("decrypt","1"):
        encrypted_text = input("Enter encrypted text (base64): ")
        encrypted_data = decode_base64(encrypted_text)
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key[:key_size_bytes], AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print("Decrypted text:", decrypted_data.decode())

def rsa_encrypt_decrypt(operation):
    key_size = int(input("Choose RSA key size (1: 1024-bit, 2: 2048-bit, 3: 4096-bit): "))
    if key_size not in rsa_key_sizes:
        print("Invalid key size.")
        return

    rsa_key = RSA.generate(rsa_key_sizes[key_size][1])
    if operation == "encrypt":
        public_key = rsa_key.publickey()
        data = input("Enter data to encrypt: ").encode()
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        print("Encrypted data (base64):", encode_base64(encrypted_data))
    elif operation == "decrypt":
        private_key = rsa_key
        encrypted_data = decode_base64(input("Enter encrypted data (base64): "))
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)
        print("Decrypted data:", decrypted_data.decode())

def main():
    while True:
        print("\nOptions:")
        print("1: Hash a string")
        print("2: Crack a hash")
        print("3: AES Encryption/Decryption")
        print("4: RSA Encryption/Decryption")
        print("5: Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            hash_type = choose_hash_type()
            if hash_type:
                hash_string(hash_type)
        elif choice == '2':
            hash_cracking()
        elif choice == '3':
            operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt","1", "decrypt","2"):
                aes_encrypt_decrypt(operation)
            else:
                print("Invalid operation.")
        elif choice == '4':
            operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt","1", "decrypt","2"):
                rsa_encrypt_decrypt(operation)
            else:
                print("Invalid operation.")
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

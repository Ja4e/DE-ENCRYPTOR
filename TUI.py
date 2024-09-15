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
from prettytable import PrettyTable
from colorama import Fore, Style, init

init(autoreset=True)

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
    "MD4": lambda data: MD4.new(data),
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
    "SHA-512/224": "1900",
    "SHA-512/256": "1910",
    "MD5": "0",
    "MD4": "900",
    "SHA1": "100",
    "SHA3-224": "17300",
    "SHA3-256": "17400",
    "SHA3-384": "17500",
    "SHA3-512": "17600",
    "BLAKE2b": "600",
}

# Function to get file path, either use existing or provide a new one
def get_file_path(prompt, default_path=None):
    while True:
        if default_path and os.path.isfile(default_path):
            choice = input(f"File found at {default_path}. Use this file? (yes/no): ").strip().lower()
            if choice == 'yes':
                return default_path
        
        file_path = input(prompt).strip()
        if os.path.isfile(file_path):
            return file_path
        else:
            print(Fore.RED + "File does not exist. Please provide a valid file path.")


def generate_rsa_key_pair(key_size):
    rsa_key = RSA.generate(key_size)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    print(Fore.GREEN + "Private Key saved as 'private_key.pem'.")

    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print(Fore.GREEN + "Public Key saved as 'public_key.pem'.")

    return private_key, public_key

def aes_encrypt_decrypt(operation):
    print("\n" + Fore.GREEN + "AES Encryption/Decryption".upper())
    key_size = int(input(Fore.CYAN + "Choose AES key size (1: 128-bit, 2: 192-bit, 3: 256-bit): "))
    
    if key_size not in aes_options:
        print(Fore.RED + "Invalid AES key size.")
        return

    key_size_bytes = aes_options[key_size][1]

    if operation in ("ENCRYPT", "1", "ENCRYPTION"):
        key_choice = input(Fore.CYAN + "Do you want to load the AES key from a file, enter it manually, or generate a new one? (file/manual/generate): ").strip().lower()
        if key_choice in ("file", "f", "1"):
            key_path = input(Fore.CYAN + "Enter the path to the AES key file: ").strip()
            if os.path.isfile(key_path):
                with open(key_path, "rb") as f:
                    aes_key = f.read()
            else:
                print(Fore.RED + "AES key file does not exist.")
                key_choice = input(Fore.CYAN + "Would you like to enter the key manually or generate a new one? (manual/generate): ").strip().lower()
                if key_choice == "manual":
                    aes_key = input(Fore.CYAN + f"Enter the AES key ({key_size_bytes * 8}-bit): ").strip().encode()
                    if len(aes_key) != key_size_bytes:
                        print(Fore.RED + "AES key length is incorrect. Ensure it matches the selected key size.")
                        return
                elif key_choice == "generate":
                    aes_key = get_random_bytes(key_size_bytes)
                    print(Fore.GREEN + "Generated new AES key:", encode_base64(aes_key))
                else:
                    print(Fore.RED + "Invalid choice.")
                    return
        elif key_choice in ("manual", "m", "2"):
            aes_key = input(Fore.CYAN + f"Enter the AES key ({key_size_bytes * 8}-bit): ").strip().encode()
            if len(aes_key) != key_size_bytes:
                print(Fore.RED + "AES key length is incorrect. Ensure it matches the selected key size.")
                return
        elif key_choice in ("generate", "g", "3"):
            aes_key = get_random_bytes(key_size_bytes)
            print(Fore.GREEN + "Generated new AES key:", encode_base64(aes_key))
        else:
            print(Fore.RED + "Invalid choice.")
            return

        iv_choice = input(Fore.CYAN + "Do you want to load the IV from a file, enter it manually, or generate a new one? (file/manual/generate): ").strip().lower()
        if iv_choice in ("file", "f", "1"):
            iv_path = input(Fore.CYAN + "Enter the path to the IV file: ").strip()
            if os.path.isfile(iv_path):
                with open(iv_path, "rb") as f:
                    iv = f.read()
            else:
                print(Fore.RED + "IV file does not exist.")
                iv_choice = input(Fore.CYAN + "Would you like to enter the IV manually or generate a new one? (manual/generate): ").strip().lower()
                if iv_choice == "manual":
                    iv = input(Fore.CYAN + "Enter the IV (16-byte): ").strip().encode()
                    if len(iv) != AES.block_size:
                        print(Fore.RED + "IV length is incorrect. Ensure it matches the AES block size.")
                        return
                elif iv_choice == "generate":
                    iv = get_random_bytes(AES.block_size)
                    print(Fore.GREEN + "Generated new IV:", encode_base64(iv))
                else:
                    print(Fore.RED + "Invalid choice.")
                    return
        elif iv_choice in ("manual", "m", "2"):
            iv = input(Fore.CYAN + "Enter the IV (16-byte): ").strip().encode()
            if len(iv) != AES.block_size:
                print(Fore.RED + "IV length is incorrect. Ensure it matches the AES block size.")
                return
        elif iv_choice in ("generate", "g", "3"):
            iv = get_random_bytes(AES.block_size)
            print(Fore.GREEN + "Generated new IV:", encode_base64(iv))
        else:
            print(Fore.RED + "Invalid choice.")
            return

        # AES Encryption
        data = input(Fore.CYAN + "Enter plaintext to encrypt: ").encode()
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))
        encrypted_data_base64 = encode_base64(iv + encrypted_data)
        print(Fore.GREEN + "Encrypted text (base64):", encrypted_data_base64)

        # Save AES key and IV after encryption
        if key_choice in ("generate", "g", "3"):
            with open("aes_key.bin", "wb") as key_file:
                key_file.write(aes_key)
            print(Fore.GREEN + "AES Key saved as 'aes_key.bin'.")

        if iv_choice in ("generate", "g", "3"):
            with open("aes_iv.bin", "wb") as iv_file:
                iv_file.write(iv)
            print(Fore.GREEN + "AES IV saved as 'aes_iv.bin'.")

    elif operation in ("DECRYPT", "2", "DECRYPTION"):
        # Load AES key
        if not os.path.isfile("aes_key.bin"):
            print(Fore.RED + "AES key file does not exist.")
            while True:
                key_choice = input(Fore.CYAN + "Would you like to provide the AES key as text or from a file? (text/file): ").strip().lower()
                if key_choice in ("file","2"):
                    key_path = input(Fore.CYAN + "Enter the path to the AES key file: ").strip()
                    if os.path.isfile(key_path):
                        with open(key_path, "rb") as key_file:
                            aes_key = key_file.read()
                        break
                    else:
                        print(Fore.RED + "AES key file does not exist. Please check the path and try again.")
                elif key_choice in ("text","1"):
                    aes_key = input(Fore.CYAN + f"Enter the AES key ({key_size_bytes * 8}-bit): ").strip().encode()
                    if len(aes_key) != key_size_bytes:
                        print(Fore.RED + "AES key length is incorrect. Ensure it matches the selected key size.")
                        continue
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please enter 'text' or 'file'.")
        else:
            with open("aes_key.bin", "rb") as key_file:
                aes_key = key_file.read()

        # Load IV
        if not os.path.isfile("aes_iv.bin"):
            print(Fore.RED + "IV file does not exist.")
            while True:
                iv_choice = input(Fore.CYAN + "Would you like to provide the IV as text or from a file? (text/file): ").strip().lower()
                if iv_choice in ("file","2"):
                    iv_path = input(Fore.CYAN + "Enter the path to the IV file: ").strip()
                    if os.path.isfile(iv_path):
                        with open(iv_path, "rb") as iv_file:
                            iv = iv_file.read()
                        break
                    else:
                        print(Fore.RED + "IV file does not exist. Please check the path and try again.")
                elif iv_choice in ("text","1"):
                    iv = input(Fore.CYAN + "Enter the IV (16-byte): ").strip().encode()
                    if len(iv) != AES.block_size:
                        print(Fore.RED + "IV length is incorrect. Ensure it matches the AES block size.")
                        continue
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please enter 'text' or 'file'.")
        else:
            with open("aes_iv.bin", "rb") as iv_file:
                iv = iv_file.read()

        # Decrypt AES data
        source_choice = input(Fore.CYAN + "Do you want to provide the encrypted data as text or from a file? (text/file): ").strip().lower()
        if source_choice == "file":
            file_path = input(Fore.CYAN + "Enter the path to the encrypted data file: ").strip()
            if os.path.isfile(file_path):
                with open(file_path, "rb") as f:
                    encrypted_data_base64 = f.read().decode()
            else:
                print(Fore.RED + "Encrypted data file does not exist. Please check the path and try again.")
                return
        elif source_choice == "text":
            encrypted_data_base64 = input(Fore.CYAN + "Enter encrypted data (base64): ")
        else:
            print(Fore.RED + "Invalid choice.")
            return

        encrypted_data = decode_base64(encrypted_data_base64)
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        try:
            decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
            print(Fore.GREEN + "Decrypted text:", decrypted_data.decode())
        except (ValueError, KeyError) as e:
            print(Fore.RED + f"Decryption failed: {e}")

    else:
        print(Fore.RED + "Invalid operation.")




def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded_data):
    try:
        # Ensure input is a string and strip any extraneous whitespace
        if isinstance(encoded_data, bytes):
            encoded_data = encoded_data.decode('utf-8')
        encoded_data = encoded_data.strip()

        # Add padding if necessary
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)

        return base64.b64decode(encoded_data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
        return None

def hash_string(hash_type):
    print("\n" + Fore.GREEN + "Hashing Options")
    source_type = input(Fore.CYAN + "Hash text or file content? (text/file): ").strip().lower()
    
    if source_type in ("file", "2"):
        file_path = input(Fore.CYAN + "Enter the path to the file: ").strip()
        if not os.path.isfile(file_path):
            print(Fore.RED + "File does not exist. Please check the path and try again.")
            return
        with open(file_path, "rb") as file:
            data = file.read()
    elif source_type in ("text", "1"):
        data = input(Fore.CYAN + f"Enter a string to hash with {hash_type}: ").encode('utf-8')
    else:
        print(Fore.RED + "Invalid choice.")
        return

    if hash_type in hash_functions:
        hash_func = hash_functions[hash_type]
        if hash_type in ["SHAKE128", "SHAKE256"]:
            length = int(input(Fore.CYAN + "Enter output length (bytes): "))
            hashed_value = hash_func(data, length).hex()
        elif hash_type in ["cSHAKE128", "cSHAKE256"]:
            customization = input(Fore.CYAN + "Enter customization string: ")
            length = int(input(Fore.CYAN + "Enter output length (bytes): "))
            hashed_value = hash_func(data, length, customization).hex()
        elif hash_type in ["KMAC128", "KMAC256"]:
            key = os.urandom(16) if hash_type == "KMAC128" else os.urandom(32)
            customization = input(Fore.CYAN + "Enter customization string: ")
            hashed_value = hash_func(data, key, customization).hex()
        elif hash_type == "Poly1305":
            key = os.urandom(32)
            hashed_value = hash_func(data, key).hex()
        else:
            hashed_value = hash_func(data).hex() if hash_type in ["SHA-512/224", "SHA-512/256"] else hash_func(data).hexdigest()

        base64_encode = input(Fore.CYAN + "Do you want to encode the hash in Base64? (yes/no): ").strip().lower()
        if base64_encode in ("yes", "y"):
            hashed_value = encode_base64(hashed_value.encode('utf-8'))

        print(Fore.GREEN + f"{hash_type} Hash: {hashed_value}")
    else:
        print(Fore.RED + "Unsupported hash type.")


def hash_cracking():
    hash_type = choose_hash_type()
    if not hash_type:
        return

    hash_mode = hashcat_modes.get(hash_type)
    if not hash_mode:
        print(Fore.RED + "Hash mode not defined for this hash type.")
        return

    use_file = input(Fore.CYAN + f"Is the {hash_type} hash in a file? (yes/no): ").strip().lower()
    
    if use_file in ("yes", "y"):
        file_path = input(Fore.CYAN + f"Enter the path to the file containing the {hash_type} hash: ").strip()
        if not os.path.isfile(file_path):
            print(Fore.RED + "File does not exist. Please check the path and try again.")
            return
        with open(file_path, "r") as f:
            hash_to_crack = f.read().strip()
    else:
        hash_to_crack = input(Fore.CYAN + f"Enter the {hash_type} hash you want to crack: ").strip()
    
    base64_decode = input(Fore.CYAN + "Do you need to decode this hash from Base64? (yes/no): ").strip().lower()
    if base64_decode in ("yes", "y"):
        hash_to_crack = decode_base64(hash_to_crack).decode('utf-8')

    hash_file = "hash_to_crack.txt"
    with open(hash_file, "w") as f:
        f.write(hash_to_crack + "\n")
    
    try:
        wordlist_path = input(Fore.CYAN + "Enter the path to your wordlist file (leave blank for brute-force): ").strip()
        
        if not wordlist_path:
            print(Fore.YELLOW + "No wordlist provided. Switching to combinatorial attack...")
            no_symbols = input(Fore.CYAN + "No symbols in the ouput (yes/no)?: ").strip().lower()
            if no_symbols in ("yes", "y", "1"):
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-1', '?l?u?d', '-i', '?1?1?1?1?1?1?1?1']
            else:
                print(Fore.YELLOW + "WARNING! It will take a long time to crack if the hash is complex or long. Long passwords increase cracking time exponentially.")
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-i', '?a?a?a?a?a?a?a?a']
        else:
            if not os.path.isfile(wordlist_path):
                print(Fore.RED + "Wordlist file does not exist. Please check the path and try again.")
                return
            command = ['hashcat', '-m', hash_mode, hash_file, wordlist_path, '--force']
            print(Fore.GREEN + f"Dictionary attack command: {' '.join(command)}")

        # Ask if password length is less than 32
        short_password = input(Fore.CYAN + "Is the password length less than 32 characters? (yes/no): ").strip().lower()
        if short_password in ("yes", "y"):
            command.append('-O')  # Append -O for optimized kernel
        
        # Ask if going for maximum performance
        performance_mode = input(Fore.CYAN + "Do you want to use maximum performance? (yes/no): ").strip().lower()
        if performance_mode in ("yes", "y"):
            command.append('-w')
            command.append('3')  # Append -w 3 for maximum performance

        subprocess.run(command, check=True)
        print(Fore.GREEN + "Cracking complete. If Hashcat quit without showing the password, check ~/.local/share/hashcat/hashcat.potfile.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Hashcat error: {e}")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nProgram interrupted. Exiting...")
    finally:
        if os.path.isfile(hash_file):
            os.remove(hash_file)




def choose_hash_type():
    print("\n" + Fore.GREEN + "Available hash types:")
    table = PrettyTable()
    table.field_names = ["Number", "Hash Type"]
    for i, hash_type in enumerate(hash_functions.keys(), 1):
        table.add_row([i, hash_type])
    print(table)

    choice = int(input(Fore.CYAN + "Choose a hash type by number: "))
    if 1 <= choice <= len(hash_functions):
        return list(hash_functions.keys())[choice - 1]
    else:
        print(Fore.RED + "Invalid choice.")
        return None

def get_file_path(prompt, default_path=None):
    while True:
        if default_path and os.path.isfile(default_path):
            choice = input(f"File found at {default_path}. Use this file? (yes/no): ").strip().lower()
            if choice == 'yes':
                return default_path
        
        file_path = input(prompt).strip()
        if os.path.isfile(file_path):
            return file_path
        else:
            print(Fore.RED + "File does not exist. Please provide a valid file path.")

def combined_aes_rsa_encrypt_decrypt(operation):
    print("\n" + Fore.GREEN + "Combined AES-256 and RSA-4096 Encryption/Decryption".upper())

    if operation in ("encrypt", "1", "ENCRYPTION"):
        # Check if RSA keys exist and prompt user to use existing ones or generate new ones
        if os.path.isfile("private_key.pem") and os.path.isfile("public_key.pem"):
            use_existing_rsa = input(Fore.CYAN + "RSA keys found. Do you want to use existing RSA keys? (yes/no): ").strip().lower()
            if use_existing_rsa in ("no", "n"):
                rsa_key_size = 3  # RSA-4096
                rsa_key_sizes = {3: (4096, 4096)}  # Example dictionary
                rsa_key_bits = rsa_key_sizes[rsa_key_size][1]
                rsa_key = RSA.generate(rsa_key_bits)
                rsa_public_key = rsa_key.publickey()
                rsa_private_key = rsa_key

                # Save RSA private key
                with open("private_key.pem", "wb") as priv_file:
                    priv_file.write(rsa_private_key.export_key())
                print(Fore.GREEN + "RSA Private Key saved as 'private_key.pem'.")

                # Save RSA public key
                with open("public_key.pem", "wb") as pub_file:
                    pub_file.write(rsa_public_key.export_key())
                print(Fore.GREEN + "RSA Public Key saved as 'public_key.pem'.")
            else:
                with open("private_key.pem", "rb") as priv_file:
                    rsa_private_key = RSA.import_key(priv_file.read())
                with open("public_key.pem", "rb") as pub_file:
                    rsa_public_key = RSA.import_key(pub_file.read())
        else:
            rsa_key_size = 3  # RSA-4096
            rsa_key_sizes = {3: (4096, 4096)}  # Example dictionary
            rsa_key_bits = rsa_key_sizes[rsa_key_size][1]
            rsa_key = RSA.generate(rsa_key_bits)
            rsa_public_key = rsa_key.publickey()
            rsa_private_key = rsa_key

            # Save RSA private key
            with open("private_key.pem", "wb") as priv_file:
                priv_file.write(rsa_private_key.export_key())
            print(Fore.GREEN + "RSA Private Key saved as 'private_key.pem'.")

            # Save RSA public key
            with open("public_key.pem", "wb") as pub_file:
                pub_file.write(rsa_public_key.export_key())
            print(Fore.GREEN + "RSA Public Key saved as 'public_key.pem'.")

        # Prompt user for AES key or generate one
        if os.path.isfile("aes_key.bin"):
            use_existing_aes = input(Fore.CYAN + "AES key found. Do you want to use existing AES key? (yes/no): ").strip().lower()
            if use_existing_aes in ("no", "n"):
                aes_key = get_random_bytes(32)  # AES-256
                print(Fore.GREEN + "Generated AES Key (base64):", encode_base64(aes_key))

                # Save AES key
                with open("aes_key.bin", "wb") as aes_file:
                    aes_file.write(aes_key)
                print(Fore.GREEN + "AES Key saved as 'aes_key.bin'.")
            else:
                with open("aes_key.bin", "rb") as aes_file:
                    aes_key = aes_file.read()
        else:
            aes_key_provided = input(Fore.CYAN + "Do you want to provide an AES key? (yes/no): ").strip().lower()
            if aes_key_provided in ("yes", "1"):
                aes_key_base64 = input(Fore.CYAN + "Enter the AES key (base64): ").strip()
                aes_key = decode_base64(aes_key_base64)
            else:
                aes_key = get_random_bytes(32)  # AES-256
                print(Fore.GREEN + "Generated AES Key (base64):", encode_base64(aes_key))

            # Save AES key
            with open("aes_key.bin", "wb") as aes_file:
                aes_file.write(aes_key)
            print(Fore.GREEN + "AES Key saved as 'aes_key.bin'.")

        # Generate and save IV
        if os.path.isfile("iv.bin"):
            use_existing_iv = input(Fore.CYAN + "IV file found. Do you want to use existing IV? (yes/no): ").strip().lower()
            if use_existing_iv in ("no", "n"):
                iv = get_random_bytes(AES.block_size)
                print(Fore.GREEN + "Generated IV (base64):", encode_base64(iv))

                # Save IV
                with open("iv.bin", "wb") as iv_file:
                    iv_file.write(iv)
                print(Fore.GREEN + "IV saved as 'iv.bin'.")
            else:
                with open("iv.bin", "rb") as iv_file:
                    iv = iv_file.read()
        else:
            iv = get_random_bytes(AES.block_size)
            print(Fore.GREEN + "Generated IV (base64):", encode_base64(iv))

            # Save IV
            with open("iv.bin", "wb") as iv_file:
                iv_file.write(iv)
            print(Fore.GREEN + "IV saved as 'iv.bin'.")

        # Encrypt
        source_type = input(Fore.CYAN + "Encrypt from text or file? (text/file): ").strip().lower()
        if source_type in ("file", "2"):
            file_path = input(Fore.CYAN + "Enter the path to the file: ").strip()
            if not os.path.isfile(file_path):
                print(Fore.RED + "File does not exist. Please check the path and try again.")
                return
            with open(file_path, "rb") as file:
                plaintext = file.read()
        elif source_type in ("text", "1"):
            plaintext = input(Fore.CYAN + "Enter the text to encrypt: ").encode()
        else:
            print(Fore.RED + "Invalid choice.")
            return

        # AES encryption
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))

        # RSA encryption
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_key = rsa_cipher.encrypt(aes_key)
        encrypted_data = iv + ciphertext

        # Output
        print(Fore.GREEN + "Encrypted AES Key (base64):", encode_base64(encrypted_key))
        print(Fore.GREEN + "Encrypted Data (base64):", encode_base64(encrypted_data))

    elif operation in ("decrypt", "2", "DECRYPTION"):
        # Load AES key
        aes_key_path = get_file_path(
            "Enter the path to the AES key file (aes_key.bin): ", 
            "aes_key.bin"
        )
        with open(aes_key_path, "rb") as aes_file:
            aes_key = aes_file.read()

        # Load RSA private key
        private_key_path = get_file_path(
            "Enter the path to the private key file (private_key.pem): ", 
            "private_key.pem"
        )
        with open(private_key_path, "rb") as priv_file:
            rsa_private_key = RSA.import_key(priv_file.read())

        # Prompt for the encrypted AES key
        key_source = input(Fore.CYAN + "Is the encrypted AES key provided as text or from file? (text/file): ").strip().lower()
        if key_source in ("file", "2"):
            encrypted_key_file_path = input(Fore.CYAN + "Enter the path to the encrypted AES key file: ").strip()
            if not os.path.isfile(encrypted_key_file_path):
                print(Fore.RED + "Encrypted AES key file does not exist. Please check the path and try again.")
                return
            with open(encrypted_key_file_path, "rb") as key_file:
                encrypted_key = key_file.read()
        elif key_source in ("text", "1"):
            encrypted_key_base64 = input(Fore.CYAN + "Enter the encrypted AES key (base64): ").strip()
            encrypted_key = decode_base64(encrypted_key_base64)
        else:
            print(Fore.RED + "Invalid choice.")
            return

        # RSA decryption
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        try:
            aes_key = rsa_cipher.decrypt(encrypted_key)
        except ValueError as e:
            print(Fore.RED + f"Decryption failed: {e}")
            return

        # Prompt for the encrypted data
        encrypted_data_base64 = input(Fore.CYAN + "Enter the encrypted data (base64): ").strip()
        encrypted_data = decode_base64(encrypted_data_base64)

        # Extract IV and ciphertext
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]

        # AES decryption
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        try:
            decrypted_data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
            print(Fore.GREEN + "Decrypted Data:", decrypted_data.decode())
        except (ValueError, KeyError) as e:
            print(Fore.RED + f"Decryption failed: {e}")

    else:
        print(Fore.RED + "Invalid operation.")


def rsa_encrypt_decrypt(operation):
    print("\n" + Fore.GREEN + "RSA Encryption/Decryption".upper())
    key_size = int(input(Fore.CYAN + "Choose RSA key size (1: 1024-bit, 2: 2048-bit, 3: 4096-bit): "))
    if key_size not in rsa_key_sizes:
        print(Fore.RED + "Invalid key size.")
        return

    if operation in ("ENCRYPT", "1", "ENCRYPTION"):
        public_key_choice = input(Fore.CYAN + "Do you want to load the RSA public key from a file? (yes/no): ").strip().lower()
        if public_key_choice in ("yes", "y"):
            public_key_path = input(Fore.CYAN + "Enter the path to the public key file: ").strip()
            if not os.path.isfile(public_key_path):
                print(Fore.RED + "Public key file does not exist. Please check the path and try again.")
                return
            with open(public_key_path, "rb") as f:
                public_key = RSA.import_key(f.read())
        else:
            private_key, public_key = generate_rsa_key_pair(rsa_key_sizes[key_size][1])
            public_key = RSA.import_key(public_key)  # Reimport public key to use for encryption

        # Generate and output AES key
        aes_key = get_random_bytes(32)  # AES-256 key
        print(Fore.GREEN + "Generated AES Key (base64):", encode_base64(aes_key))

        data = input(Fore.CYAN + "Enter data to encrypt: ").encode()
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        print(Fore.GREEN + "Encrypted data (base64):", encode_base64(encrypted_data))

    elif operation in ("DECRYPT", "2", "DECRYPTION"):
        private_key_choice = input(Fore.CYAN + "Do you want to load the RSA private key from a file? (yes/no): ").strip().lower()
        if private_key_choice in ("yes", "y"):
            private_key_path = input(Fore.CYAN + "Enter the path to the private key file: ").strip()
            if not os.path.isfile(private_key_path):
                print(Fore.RED + "Private key file does not exist. Please check the path and try again.")
                return
            with open(private_key_path, "rb") as f:
                private_key = RSA.import_key(f.read())
        else:
            print(Fore.RED + "Private key file required for decryption. Please provide a valid file or use the existing one.")
            return

        encrypted_data_base64 = input(Fore.CYAN + "Enter encrypted data (base64): ")
        encrypted_data = decode_base64(encrypted_data_base64)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            decrypted_data = cipher_rsa.decrypt(encrypted_data)
            print(Fore.GREEN + "Decrypted data:", decrypted_data.decode())
        except (ValueError, TypeError) as e:
            print(Fore.RED + f"Decryption failed: {e}")
    else:
        print(Fore.RED + "Invalid operation.")



def main():
    while True:
        print("\n" + Fore.GREEN + "Options:")
        table = PrettyTable()
        table.field_names = ["Option", "Description"]
        table.add_row(["1", "Hash a string"])
        table.add_row(["2", "Crack a hash"])
        table.add_row(["3", "AES Encryption/Decryption"])
        table.add_row(["4", "RSA Encryption/Decryption"])
        table.add_row(["5", "Combined AES-256 and RSA-4096 Encryption/Decryption"])
        table.add_row(["6", "Exit"])
        print(table)

        choice = input(Fore.CYAN + "Choose an option: ")

        if choice == '1':
            hash_type = choose_hash_type()
            if hash_type:
                hash_string(hash_type)
        elif choice == '2':
            hash_cracking()
        elif choice == '3':
            operation = input(Fore.CYAN + "\nChoose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt", "1", "decrypt", "2"):
                aes_encrypt_decrypt(operation)
            else:
                print(Fore.RED + "Invalid operation.")
        elif choice == '4':
            operation = input(Fore.CYAN + "\nChoose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt", "1", "decrypt", "2"):
                rsa_encrypt_decrypt(operation)
            else:
                print(Fore.RED + "Invalid operation.")
        elif choice == '5':
            operation = input(Fore.CYAN + "\nChoose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt", "1", "decrypt", "2"):
                combined_aes_rsa_encrypt_decrypt(operation)
            else:
                print(Fore.RED + "Invalid operation.")
        elif choice == '6':
            break
        else:
            print(Fore.RED + "Invalid choice.")


if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nProgram interrupted. Exiting...")
            break

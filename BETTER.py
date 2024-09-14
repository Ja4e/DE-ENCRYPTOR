import hashlib
import subprocess
import os
import base64
from Crypto.Hash import MD4
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Random import get_random_bytes
from fuzzywuzzy import process

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
    return base64.b64decode(encoded_data).decode('utf-8')

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

def crack_hash(hash_type):
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
    
    if subprocess.call(['which', 'hashcat'], stdout=subprocess.DEVNULL) != 0:
        print("Hashcat is not installed on this system. Please install it and try again.")
        return
    
    hash_file = "hash_to_crack.txt"
    with open(hash_file, "w") as f:
        f.write(hash_to_crack + "\n")
    
    try:
        if wordlist_path == "":
            print("No wordlist provided. Switching to combinatorial attack...")
            no_symbols = input("No symbols (yes/no)?: ").strip().lower()
            if no_symbols in ("yes", "y"):
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-1', '?l?u?d', '-i', '?1?1?1?1?1?1?1?1']
            else:
                print("WARNING! It will take a long time to crack if the hash is complex or long. Long passwords increase cracking time exponentially.")
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-i', '?a?a?a?a?a?a?a?a']
        else:
            command = ['hashcat', '-m', hash_mode, hash_file, wordlist_path, '--force']
            print(f"Dictionary attack command: {' '.join(command)}")
        subprocess.run(command)

    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
    finally:
        os.remove(hash_file)

def base64_action():
    action = input("Do you want to encode or decode in Base64? (encode/decode): ").strip().lower()
    if action == "encode":
        data = input("Enter the data to encode: ")
        encoded_data = encode_base64(data.encode('utf-8'))
        print("Encoded Base64:", encoded_data)
    elif action == "decode":
        encoded_data = input("Enter the Base64 encoded data: ")
        try:
            decoded_data = decode_base64(encoded_data.encode('utf-8'))
            print("Decoded data:", decoded_data)
        except Exception as e:
            print(f"Error decoding Base64: {e}")
    else:
        print("Invalid action. Please choose 'encode' or 'decode'.")

def handle_action(hash_type, action):
    if action in ("HASH", "1"):
        hash_string(hash_type)
    elif action in ("CRACK", "2"):
        crack_hash(hash_type)
    elif action in ("BASE64", "3"):
        base64_action()
    else:
        print("Please choose 'HASH' (1), 'CRACK' (2), or 'BASE64' (3).")

def display_and_select_options(choices):
    print("Available options:")
    for i, (option, score) in enumerate(choices, start=1):
        print(f"{i}. {option} (Score: {score})")
    
    print("Options:")
    print(f"{len(choices) + 1}. Base64 Encoding/Decoding")
    
    try:
        selection = int(input(f"Select an option (1-{len(choices) + 1}): "))
        if 1 <= selection <= len(choices):
            return choices[selection - 1][0]
        elif selection == len(choices) + 1:
            return "Base64"
        else:
            print("Invalid selection. Please choose a number from the list.")
            return None
    except ValueError:
        print("Invalid input. Please enter a number.")
        return None

while True:
    try:
        b = input("Choose hash type (SHA-512, SHA-256, MD5, MD4, etc.) or 'BASE64': ").upper()
        hash_types = list(hashcat_modes.keys())
        if b == "BASE64":
            handle_action(b, "3")
        else:
            matches = process.extract(b, hash_types, limit=6)
            if matches:
                selected_hash_type = display_and_select_options(matches)
                if selected_hash_type:
                    print(f"Selected option: {selected_hash_type}")
                    a = input(f"HASH or CRACK {selected_hash_type}: ").upper()
                    handle_action(selected_hash_type, a)
            else:
                print("No matches found. Please choose a valid hash type.")
    
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
        break

import hashlib
import os
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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

def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded_data):
    try:
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
        print("3. Encrypt AES")
        print("4. Decrypt AES")
        print("5. Encrypt RSA")
        print("6. Decrypt RSA")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '3':
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

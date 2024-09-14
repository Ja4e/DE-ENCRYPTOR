import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Define AES options and RSA key sizes
aes_options = {
    1: ("AES-128", 16),
    2: ("AES-192", 24),
    3: ("AES-256", 32),
    4: ("AES-512", 64),  # Custom addition, not a standard AES key size
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
        # Add padding if necessary
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        return base64.b64decode(encoded_data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
        return None

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

def select_aes_type():
    print("Available AES types:")
    for i, (desc, _) in aes_options.items():
        print(f"{i}. {desc}")
    selected_option = int(input("Enter your choice: "))
    return aes_options.get(selected_option, None)

def select_rsa_key_size():
    print("Available RSA key sizes:")
    for i, (desc, _) in rsa_key_sizes.items():
        print(f"{i}. {desc}")
    selected_option = int(input("Enter your choice: "))
    return rsa_key_sizes.get(selected_option, None)

def main():
    while True:
        print("Options:")
        print("1. Encrypt AES")
        print("2. Decrypt AES")
        print("3. Encrypt RSA")
        print("4. Decrypt RSA")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            aes_type = select_aes_type()
            if aes_type:
                key = get_random_bytes(aes_type[1])
                plaintext = input("Enter plaintext: ").encode('utf-8')
                ciphertext, iv = aes_encrypt(plaintext, key)
                if ciphertext:
                    print(f"Encrypted ciphertext (base64): {encode_base64(ciphertext)}")
                    print(f"IV (base64): {encode_base64(iv)}")
            else:
                print("Invalid AES type selected")
        elif choice == '2':
            aes_type = select_aes_type()
            if aes_type:
                key = get_random_bytes(aes_type[1])
                iv = decode_base64(input("Enter IV (base64): "))
                ciphertext = decode_base64(input("Enter ciphertext (base64): "))
                plaintext = aes_decrypt(ciphertext, key, iv)
                if plaintext:
                    print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
            else:
                print("Invalid AES type selected")
        elif choice == '3':
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
        elif choice == '4':
            private_key_path = input("Enter the path to the private key file (PEM): ")
            with open(private_key_path, 'rb') as key_file:
                private_key = key_file.read()
            
            ciphertext = decode_base64(input("Enter ciphertext (base64): "))
            plaintext = rsa_decrypt(ciphertext, private_key)
            if plaintext:
                print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
        elif choice == '5':
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

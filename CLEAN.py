import hashlib
import os
import base64
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD4, HMAC, SHA1, SHA256
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
        # Add padding if necessary
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        return base64.b64decode(encoded_data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
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

    if operation in ("encrypt", "1"):
        plaintext = input("Enter plaintext to encrypt: ").encode()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        print("Encrypted text (base64):", encode_base64(iv + ciphertext))
    elif operation in ("decrypt", "2"):
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
        print("1: AES Encryption/Decryption")
        print("2: RSA Encryption/Decryption")
        print("3: Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt", "1", "decrypt", "2"):
                aes_encrypt_decrypt(operation)
            else:
                print("Invalid operation.")
        elif choice == '2':
            operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
            if operation in ("encrypt", "1", "decrypt", "2"):
                rsa_encrypt_decrypt(operation)
            else:
                print("Invalid operation.")
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

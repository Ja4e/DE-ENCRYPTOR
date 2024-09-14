Hash Functions and Hashcat Modes
Hash Functions

The following hash functions are supported for hashing data:

    SHA Family:
        SHA-512
        SHA-256
        SHA-384
        SHA-224
        SHA-512/224
        SHA-512/256

    MD Family:
        MD5
        MD4

    SHA3 Family:
        SHA3-224
        SHA3-256
        SHA3-384
        SHA3-512

    BLAKE2 Family:
        BLAKE2s
        BLAKE2b


Hashcat Modes currently only implemented (you can add them directly from the hashcat --help into the dictionary)

The following modes correspond to the hash functions used for hash cracking with Hashcat:

    SHA Family:
        SHA-512: 1700
        SHA-256: 1400
        SHA-384: 10800
        SHA-224: 1300
        SHA-512/224: 20400
        SHA-512/256: 20500

    MD Family:
        MD5: 0
        MD4: 900

    SHA3 Family:
        SHA3-224: 17300
        SHA3-256: 17400
        SHA3-384: 17500
        SHA3-512: 17600

    BLAKE2 Family:
        BLAKE2b: 600

Note: Make sure Hashcat is installed on your system to use these modes effectively.
Encryption and Decryption Types

AES Encryption/Decryption:

    AES-128: 16-byte key
    AES-192: 24-byte key
    AES-256: 32-byte key

RSA Encryption/Decryption:

    RSA-1024: 1024-bit key
    RSA-2048: 2048-bit key
    RSA-4096: 4096-bit key

Summary

    AES Encryption/Decryption: 3 key sizes (128, 192, 256 bits)
    RSA Encryption/Decryption: 3 key sizes (1024, 2048, 4096 bits)

This tool can be used to hash and dehash data, as well as to encrypt and decrypt using AES and RSA. Note that brute-forcing AES or RSA keys is currently considered infeasible.

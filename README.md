Uses hashcat
makre sure hashcat is installed
Scripts/tools

Encryption and Decryption Types:

    AES Encryption/Decryption:
        AES-128: 16-byte key
        AES-192: 24-byte key
        AES-256: 32-byte key

    RSA Encryption/Decryption:
        RSA-1024: 1024-bit key
        RSA-2048: 2048-bit key
        RSA-4096: 4096-bit key

Hashing Functions (Not Encryption/Decryption):

These hash functions can be used to hash data but not for encryption/decryption:

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

    Shake Family:
        SHAKE128
        SHAKE256

    cSHAKE Family:
        cSHAKE128
        cSHAKE256

    KMAC Family:
        KMAC128
        KMAC256

    Poly1305: (Used for authentication, not encryption/decryption)

Hashcat Modes (For Cracking Hashes):

These modes correspond to specific hashing algorithms used for hash cracking:

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
        BLAKE2b

    Other Hash Types:
        GOST R 34.11-2012 256-bit
        GOST R 34.11-2012 512-bit
        GOST R 34.11-94
        GPG
        Half MD5
        Keccak Variants
        Whirlpool
        SipHash
        HMAC Variants
        PBKDF2 Variants
        scrypt
        phpass
        TACACS+
        SIP digest authentication (MD5)
        IKE-PSK MD5
        IKE-PSK SHA1
        SNMPv3 HMAC Variants
        WPA-EAPOL Variants

Summary:

    AES Encryption/Decryption: 3 key sizes (128, 192, 256 bits)
    RSA Encryption/Decryption: 3 key sizes (1024, 2048, 4096 bits)



This tool can be used to hash and dehash and encrypt and decrypt popular

bruteforcing aes or rsa seems impossible rn

import hashlib
import subprocess
import os

def hash_string(hash_type):
    d = input(f"Enter a string to hash with {hash_type}: ")
    hash_functions = {
        "SHA-512": hashlib.sha512,
        "SHA-256": hashlib.sha256
    }
    
    if hash_type in hash_functions:
        hashed_value = hash_functions[hash_type](d.encode('utf-8')).hexdigest()
        print(f"{hash_type} Hash:", hashed_value)
    else:
        print("Unsupported hash type.")

def crack_hash(hash_type, hash_mode):
    hash_to_crack = input(f"Enter the {hash_type} hash you want to crack: ")
    wordlist_path = input("Enter the path to your wordlist file (leave blank for brute-force): ")
    if subprocess.call(['which', 'hashcat'], stdout=subprocess.DEVNULL) != 0:
        print("Hashcat is not installed on this system. Please install it and try again.")
        return
    hash_file = "hash_to_crack.txt"
    with open(hash_file, "w") as f:
        f.write(hash_to_crack + "\n")
    try:
        if wordlist_path.strip() == "":
            print("No wordlist provided. Switching to combinatorial attack...")
            a = input("No symbols (yes/no)?: ").upper()
            if a in ("YES", "Y"):
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-1', '?l?u?d', '-i', '?1?1?1?1?1?1?1?1']
            else:
                print("WARNING! It will take a long time to crack if the hash is complex or long.")
                command = ['hashcat', '-m', hash_mode, hash_file, '-a', '3', '--force', '-i', '?a?a?a?a?a?a?a?a']
        else:
            command = ['hashcat', '-m', hash_mode, hash_file, wordlist_path, '--force']
            print(f"Dictionary attack command: {' '.join(command)}")
        subprocess.run(command)

    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
    finally:
        os.remove(hash_file)

while True:
    try:
        b = input("SHA512 or SHA256 (ALL RAW): ").upper()
        
        if b in ("SHA512", "512", "1"):
            c = "SHA-512"
            mode = "1700"
            a = input(f"HASH or CRACK {c}: ").upper()
            
            if a in ("HASH", "1"):
                hash_string(c)
            elif a in ("CRACK", "2"):
                crack_hash(c, mode)
            else:
                print("Please choose 'HASH' (1) or 'CRACK' (2).")

        elif b in ("SHA256", "256", "2"):
            c = "SHA-256"
            mode = "1400"
            a = input(f"HASH or CRACK {c}: ").upper()

            if a in ("HASH", "1"):
                hash_string(c)
            elif a in ("CRACK", "2"):
                crack_hash(c, mode)
            else:
                print("Please choose 'HASH' (1) or 'CRACK' (2).")

        else:
            print("Invalid selection. Please choose SHA512 (1) or SHA256 (2).")

    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
        break

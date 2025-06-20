import os
import re
import getpass
import hashlib
import random
import string
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

def shred_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'ba+', buffering=0) as f:
            length = f.tell()
            f.seek(0)
            f.write(os.urandom(length))
        os.remove(file_path)

def get_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def generate_pattern(seed):
    hash_digest = hashlib.sha512(str(seed).encode()).hexdigest()
    random.seed(int(hash_digest, 16))
    characters = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choices(characters, k=6))

def is_generated_pattern(candidate, seed):
    return candidate == generate_pattern(seed)

def compute_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def is_dangerous_path(path):
    abs_path = os.path.abspath(path)
    pattern = re.compile(r'(^\.{1,}$)|(.*[\\/]\.{1,}$)|(^[A-Za-z]:\\?$)|(^/$)')
    return bool(pattern.match(path) or pattern.match(abs_path))

def is_script_inside_target(folder_path):
    script_dir = os.path.abspath(os.path.dirname(__file__))
    folder_path = os.path.abspath(folder_path)
    return script_dir.startswith(folder_path)

def encrypt_file(input_file, password):
    try:
        base, ext = os.path.splitext(input_file)
        parts = base.rsplit('_', 1)
        if len(parts) == 2 and len(parts[1]) == 6 and parts[1].isalnum():
            try:
                with open(input_file, 'rb') as f:
                    file_data = f.read()
                seed = int.from_bytes(file_data[:4], 'big')
                if is_generated_pattern(parts[1], seed):
                    print(f"file '{input_file}' is already encrypted and tagged. skipping...")
                    return False
            except Exception:
                pass
        seed = random.randint(1, 1 << 30)
        tag = generate_pattern(seed)
        output_file = f"{base}_{tag}{ext}"
        key, salt = get_key_from_password(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(input_file, 'rb') as f:
            file_data = f.read()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        file_hmac = compute_hmac(key, file_data)
        if os.path.exists(output_file):
            shred_file(output_file)
        with open(output_file, 'wb') as f:
            f.write(seed.to_bytes(4, 'big') + salt + iv + encrypted_data + file_hmac)
        shred_file(input_file)
        print(f"file encrypted -- {output_file}")
        return True
    except MemoryError:
        print(f"error: file '{input_file}' is too large to process in memory.")
        return False

def decrypt_file(input_file, password):
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()
        seed = int.from_bytes(file_data[:4], 'big')
        base, ext = os.path.splitext(input_file)
        parts = base.rsplit('_', 1)
        if len(parts) != 2 or not is_generated_pattern(parts[1], seed):
            print(f"decryption aborted: filename tag doesn't match embedded seed -- {input_file}")
            return False
        salt = file_data[4:20]
        iv = file_data[20:36]
        encrypted_data = file_data[36:-32]
        stored_hmac = file_data[-32:]
        key, _ = get_key_from_password(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            computed_hmac = compute_hmac(key, decrypted_data)
            if computed_hmac != stored_hmac:
                print(f"decryption failed: invalid password or file has been tampered -- {input_file}")
                return False
            original_name = parts[0] + ext
            if os.path.exists(original_name):
                shred_file(original_name)
            with open(original_name, 'wb') as f:
                f.write(decrypted_data)
            shred_file(input_file)
            print(f"file decrypted -- {original_name}")
            return True
        except Exception:
            print(f"decryption failed: invalid password or file corrupted -- {input_file}")
            return False
    except MemoryError:
        print(f"error: file '{input_file}' is too large to process in memory.")
        return False

def folder_encryption_decision(folder_path):
    encrypted = 0
    total = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            base, ext = os.path.splitext(file)
            parts = base.rsplit('_', 1)
            total += 1
            if len(parts) == 2 and len(parts[1]) == 6 and parts[1].isalnum():
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'rb') as f:
                        file_data = f.read(4)
                    seed = int.from_bytes(file_data, 'big')
                    if is_generated_pattern(parts[1], seed):
                        encrypted += 1
                except Exception:
                    pass
    if encrypted == 0:
        return 'encrypt'
    elif encrypted == total:
        return 'decrypt'
    else:
        choice = input("mixed content detected. type 'e' to encrypt all or 'd' to decrypt all: ").strip().lower()
        return 'decrypt' if choice == 'd' else 'encrypt'

def process_folder(folder_path, password):
    if is_dangerous_path(folder_path):
        print(f"error: refusing to process root or critical system path [{folder_path}]")
        return
    if is_script_inside_target(folder_path):
        print(f"error: refusing to process a folder containing this script [{folder_path}]")
        return
    action = folder_encryption_decision(folder_path)
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            if action == 'encrypt':
                encrypt_file(full_path, password)
            else:
                decrypt_file(full_path, password)

def process_path(path, password):
    if os.path.isfile(path):
        base, ext = os.path.splitext(path)
        parts = base.rsplit('_', 1)
        if len(parts) == 2 and len(parts[1]) == 6 and parts[1].isalnum():
            decrypt_file(path, password)
        else:
            encrypt_file(path, password)
    elif os.path.isdir(path):
        process_folder(path, password)
    else:
        print("error: path does not exist.")

def process_cmd(cmd):
    if cmd.lower() == 'exit':
        exit(0)
    if cmd.lower() == 'cls':
        sleep(2)
        os.system('cls' if os.name == 'nt' else 'clear')


def main():
    try:
        password = getpass.getpass("password: ")
        if not password:
            print("error: password cannot be empty.")
            exit(1)
        print(password)
        process_cmd('cls')
    except KeyboardInterrupt:
        exit(0)
    print("""
  ______                                   __            __    __ 
 /      \                                 /  |          /  |  /  |
/$$$$$$  |  ______   __    __   ______   _$$ |_         $$ |  $$ |
$$ |  $$/  /      \ /  |  /  | /      \ / $$   |        $$  \/$$/ 
$$ |      /$$$$$$  |$$ |  $$ |/$$$$$$  |$$$$$$/          $$  $$<  
$$ |   __ $$ |  $$/ $$ |  $$ |$$ |  $$ |  $$ | __         $$$$  \ 
$$ \__/  |$$ |      $$ \__$$ |$$ |__$$ |  $$ |/  |       $$ /$$  |
$$    $$/ $$ |      $$    $$ |$$    $$/   $$  $$/       $$ |  $$ |
 $$$$$$/  $$/        $$$$$$$ |$$$$$$$/     $$$$/        $$/   $$/ 
                    /  \__$$ |$$ |                                
                    $$    $$/ $$ |                                
                     $$$$$$/  $$/                                 
""")
    while True:
        try:
            path = input("> ").strip()
            process_cmd(path)
            process_path(path, password)
        except KeyboardInterrupt:
            exit(0)

if __name__ == "__main__":
    main()

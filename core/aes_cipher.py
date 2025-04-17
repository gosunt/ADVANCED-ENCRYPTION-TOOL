import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from core.utils import get_password, save_metadata, log_action

backend = default_backend()


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    return kdf.derive(password)


def encrypt_file(filepath):
    password = get_password()
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as f:
        plaintext = f.read()

    # Multi-round encryption example (2 rounds)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    cipher2 = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor2 = cipher2.encryptor()
    ciphertext = encryptor2.update(ciphertext) + encryptor2.finalize()

    with open(f'storage/encrypted/{os.path.basename(filepath)}.enc', 'wb') as f:
        f.write(salt + iv + ciphertext)
    save_metadata(filepath, salt, iv)
    log_action(f"AES Encrypted: {filepath}")
    print("[+] AES File encrypted.")


def decrypt_file(filepath):
    password = get_password()
    with open(filepath, 'rb') as f:
        data = f.read()
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password.encode(), salt)

    # Reverse multi-round decryption (2 rounds)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    cipher2 = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor2 = cipher2.decryptor()
    plaintext = decryptor2.update(plaintext) + decryptor2.finalize()

    out_file = filepath.replace(".enc", ".dec")
    with open(out_file, 'wb') as f:
        f.write(plaintext)
    log_action(f"AES Decrypted: {filepath}")
    print("[+] AES File decrypted to", out_file)
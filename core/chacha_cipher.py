import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from core.utils import get_password, save_metadata, log_action

backend = default_backend()

def derive_key(password: bytes) -> bytes:
    return password[:32].ljust(32, b'0')

def encrypt_file(filepath):
    password = get_password().encode()
    key = derive_key(password)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext)
    with open(f'storage/encrypted/{os.path.basename(filepath)}.chacha', 'wb') as f:
        f.write(nonce + ciphertext)
    save_metadata(filepath, nonce, b'')
    log_action(f"ChaCha Encrypted: {filepath}")
    print("[+] ChaCha20 File encrypted.")

def decrypt_file(filepath):
    password = get_password().encode()
    key = derive_key(password)

    with open(filepath, 'rb') as f:
        data = f.read()
    nonce, ciphertext = data[:16], data[16:]

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    out_file = filepath.replace(".chacha", ".dec")
    with open(out_file, 'wb') as f:
        f.write(plaintext)
    log_action(f"ChaCha Decrypted: {filepath}")
    print("[+] ChaCha20 File decrypted to", out_file)
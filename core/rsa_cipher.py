import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from core.utils import log_action

private_key_path = "storage/keys/rsa_private.pem"
public_key_path = "storage/keys/rsa_public.pem"

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    log_action("RSA Keys generated.")

def encrypt_file(filepath):
    if not os.path.exists(public_key_path):
        generate_keys()
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(filepath, "rb") as f:
        data = f.read()
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    with open(f"storage/encrypted/{os.path.basename(filepath)}.rsa", "wb") as f:
        f.write(ciphertext)
    log_action(f"RSA Encrypted: {filepath}")
    print("[+] RSA File encrypted.")

def decrypt_file(filepath):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(filepath, "rb") as f:
        ciphertext = f.read()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    out_file = filepath.replace(".rsa", ".dec")
    with open(out_file, "wb") as f:
        f.write(plaintext)
    log_action(f"RSA Decrypted: {filepath}")
    print("[+] RSA File decrypted to", out_file)
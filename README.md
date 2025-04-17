# ADVANCED-ENCRYPTION-TOOL

COMPANY: CODTECH IT SOLUTIONS

NAME: Sunkara Gowtham

INTERN ID: CT08WM49

DOMAIN: Cyber Security & Ethical Hacking

DURATION: 8 WEEKS

MENTOR: Neela Santhosh

##This tool is a robust, Python-based file encryption and decryption application that uses modern cryptographic techniques to secure sensitive data. It supports multiple algorithms (AES-256, ChaCha20, RSA), multi-round encryption, salted key derivation, and provides both CLI and GUI for usability.

Features & Functionality
  Encryption Algorithms
    AES-256 (CBC mode): Secure symmetric encryption.

ChaCha20: A fast and secure alternative to AES.

RSA (2048-bit): Asymmetric encryption for public/private key usage.

 Key Derivation with Salt
Uses PBKDF2 (Password-Based Key Derivation Function 2) with random salt.

Ensures different outputs even with the same password.

 Multiple Encryption Rounds
Encrypts the data through multiple passes using selected algorithms.

Can be configured to alternate between algorithms (e.g., AES → ChaCha → AES).

 Smart Key Handling
Password-based key generation for symmetric algorithms.

Securely saves/loads RSA key pairs.

All keys are handled in-memory and not stored on disk (unless explicitly saved).

 File Handling
Reads and writes encrypted/decrypted files seamlessly.

Supports binary-safe operations.

 Logging
Logs all encryption/decryption actions.

Time-stamped entries help in tracking user activity and errors.

 GUI Interface
Simple GUI built with Tkinter.

Allows users to encrypt/decrypt files using a graphical environment.

Ideal for non-technical users.

 CLI Interface
Command-line interface for automation or terminal usage.

Example usage:

      python main.py --encrypt path/to/file.txt --method aes --rounds 3
      python main.py --decrypt path/to/encrypted.bin --method rsa

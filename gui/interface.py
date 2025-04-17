import tkinter as tk
from tkinter import filedialog, messagebox
from core import aes_cipher, chacha_cipher, rsa_cipher

def launch_gui():
    root = tk.Tk()
    root.title("Encryption Tool")
    root.geometry("400x400")

    def encrypt(alg):
        path = filedialog.askopenfilename()
        if path:
            if alg == "aes":
                aes_cipher.encrypt_file(path)
            elif alg == "chacha":
                chacha_cipher.encrypt_file(path)
            elif alg == "rsa":
                rsa_cipher.encrypt_file(path)
            messagebox.showinfo("Encrypted", f"Encrypted using {alg.upper()}: {path}")

    def decrypt(alg):
        path = filedialog.askopenfilename()
        if path:
            if alg == "aes":
                aes_cipher.decrypt_file(path)
            elif alg == "chacha":
                chacha_cipher.decrypt_file(path)
            elif alg == "rsa":
                rsa_cipher.decrypt_file(path)
            messagebox.showinfo("Decrypted", f"Decrypted using {alg.upper()}: {path}")

    tk.Label(root, text="Advanced Encryption Tool", font=("Arial", 16)).pack(pady=10)

    for alg in ["aes", "chacha", "rsa"]:
        tk.Button(root, text=f"Encrypt with {alg.upper()}", command=lambda a=alg: encrypt(a), width=30).pack(pady=5)
        tk.Button(root, text=f"Decrypt with {alg.upper()}", command=lambda a=alg: decrypt(a), width=30).pack(pady=5)

    root.mainloop()
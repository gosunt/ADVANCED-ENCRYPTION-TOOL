import argparse
from core import aes_cipher, chacha_cipher, rsa_cipher
from gui.interface import launch_gui

def main():
    parser = argparse.ArgumentParser(description="Advanced Encryption Tool")
    parser.add_argument('--encrypt', help='Encrypt a file', metavar='FILE')
    parser.add_argument('--decrypt', help='Decrypt a file', metavar='FILE')
    parser.add_argument('--alg', help='Algorithm: aes | chacha | rsa', default='aes')
    parser.add_argument('--gui', help='Launch GUI', action='store_true')
    args = parser.parse_args()

    if args.gui:
        launch_gui()
    elif args.encrypt:
        if args.alg == 'aes':
            aes_cipher.encrypt_file(args.encrypt)
        elif args.alg == 'chacha':
            chacha_cipher.encrypt_file(args.encrypt)
        elif args.alg == 'rsa':
            rsa_cipher.encrypt_file(args.encrypt)
    elif args.decrypt:
        if args.alg == 'aes':
            aes_cipher.decrypt_file(args.decrypt)
        elif args.alg == 'chacha':
            chacha_cipher.decrypt_file(args.decrypt)
        elif args.alg == 'rsa':
            rsa_cipher.decrypt_file(args.decrypt)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

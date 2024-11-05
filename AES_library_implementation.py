from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import sys
import time
import sys
from hashlib import pbkdf2_hmac
import base64

def main():
    """
    This application is designed to implement and evaluate the performance of the encryption and decryption modules within the Cryptography library. 
    It takes a textual password and data from standard input and records the encryption and decryption durations in the .time folder.
    """

    if len(sys.argv) != 2:
        print("Usage: python3 AES_library_implementation.py <AES_Key> ")
        sys.exit(1)

    AES_password = sys.argv[1]
    plain = sys.stdin.read().strip()

    AES_key  = pbkdf2_hmac('sha256', AES_password.encode('utf-8'), salt=b'salt', iterations=10000, dklen=16)
    print(AES_key)
    # AES_key = AES_password.encode()

    # Create padder
    padder = padding.PKCS7(128).padder()

    plaintext_bytes = plain.encode()
    

    # Initialize cipher
    cipher = Cipher(algorithms.AES(AES_key), modes.ECB(),backend=default_backend())
    
    # Initialize encryptor
    encryptor = cipher.encryptor()

    start_time = time.time_ns()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    end_time = time.time_ns()

    time_file_enc = open(f'time/Cryptography_encrypt_times.txt', 'a')
    overall = (end_time - start_time) / (10 ** 9)
    time_file_enc.write(str('{:0.9f}\n'.format(overall)))

    # Initialize decryptor
    decryptor = cipher.decryptor()

    # Create unpadder
    unpadder = padding.PKCS7(128).unpadder()

    start_time = time.time_ns()
    padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    plain_decrypted = unpadder.update(padded_decrypted) + unpadder.finalize()
    end_time = time.time_ns()

    time_file_dec = open(f'time/Cryptography_decrypt_times.txt', 'a')
    overall = (end_time - start_time) / (10 ** 9)
    time_file_dec.write(str('{:0.9f}\n'.format(overall)))

    print(base64.b64encode(ciphertext).decode())  # Print ciphertext as hex
    print(plain_decrypted.decode())


if __name__ == "__main__":
    main()
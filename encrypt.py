import SAES
import sys
import base64
from hashlib import pbkdf2_hmac
import time

def main():
    """
    This application implements encryption for the SAES module.
    It accepts two text-based arguments as inputs: a normal AES key and an optional shuffle key (SK).
    The content to be encrypted is provided through standard input (stdin), and the ciphertext is returned through standard output (stdout).
    """
        
    if 2 > len(sys.argv) > 3:
        print("Usage: python3 encrypt.py <AES_Key> [SAES_Key]")
        sys.exit(1)
    
    AES_password = sys.argv[1]
    SAES_password = sys.argv[2] if len(sys.argv) > 2 else None
    plaintext = sys.stdin.read()

    AES_key  = pbkdf2_hmac('sha256', AES_password.encode('utf-8'), salt=b'salt', iterations=10000, dklen=16)
    SAES_key = pbkdf2_hmac('sha256', SAES_password.encode('utf-8'), salt=b'salt', iterations=10000, dklen=16) if SAES_password else None

    cryptor= SAES.new(AES_key, SAES_key)
    start_time = time.time_ns()
    ciphertext = cryptor.encrypt(plaintext)
    end_time = time.time_ns()

    time_file = open(f'time/{"saes" if SAES_key else "aes"}_encrypt_times.txt', 'a')
    overall = (end_time - start_time) / (10 ** 9)
    time_file.write(str('{:0.9f}\n'.format(overall)))

    print(base64.b64encode(ciphertext).decode('utf-8'))

if __name__ == "__main__":
    main()
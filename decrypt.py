import SAES
import sys
import base64
from hashlib import pbkdf2_hmac

def main():
    """
    This application implements decryption for the SAES module.
    It accepts two text-based arguments as inputs: a normal AES key and an optional shuffle key (SK).
    The content to be decrypted is provided through standard input (stdin), and the plaintext is returned through standard output (stdout).
    """    
    if 2 > len(sys.argv) > 3:
        print("Usage: python3 decrypt.py <AES_Key> [SAES_Key]")
        sys.exit(1)
    
    AES_password = sys.argv[1]
    SAES_password = sys.argv[2] if len(sys.argv) > 2 else None
    ciphertext = base64.b64decode(sys.stdin.read().strip())

    AES_key  = pbkdf2_hmac('sha256', AES_password.encode('utf-8'), salt=b'salt', iterations=10000, dklen=16)
    SAES_key = pbkdf2_hmac('sha256', SAES_password.encode('utf-8'), salt=b'salt', iterations=10000, dklen=16) if SAES_password else None

    decryptor= SAES.new(AES_key, SAES_key)

    print(decryptor.decrypt(ciphertext))

if __name__ == "__main__":
    main()
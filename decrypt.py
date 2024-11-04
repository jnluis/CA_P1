from SAES import SAES
import sys
import base64

def main():
    """
    This application implements decryption for the SAES module.
    It accepts two text-based arguments as inputs: a normal AES key and an optional shuffle key (SK).
    The content to be decrypted is provided through standard input (stdin), and the plaintext is returned through standard output (stdout).
    """    
    if len(sys.argv) < 2:
        print("Usage: python3 decrypt.py <AES_Key> [SAES_Key]")
        sys.exit(1)
    
    AES_key = sys.argv[1]
    SAES_key = sys.argv[2] if len(sys.argv) > 2 else None
    ciphertext = base64.b64decode(sys.stdin.read().strip())

    decryptor= SAES.new(AES_key, SAES_key)

    print(decryptor.decrypt(ciphertext))

if __name__ == "__main__":
    main()
from SAES import SAES
import sys
import base64

def main():
    """
    This application implements encryption for the SAES module.
    It accepts two text-based arguments as inputs: a normal AES key and an optional shuffle key (SK).
    The content to be encrypted is provided through standard input (stdin), and the ciphertext is returned through standard output (stdout).
    """
        
    if len(sys.argv) < 2:
        print("Usage: python3 encrypt.py <AES_Key> [SAES_Key]")
        sys.exit(1)
    
    AES_key = sys.argv[1]
    SAES_key = sys.argv[2] if len(sys.argv) > 2 else None
    plaintext = sys.stdin.read()

    cryptor= SAES.new(AES_key, SAES_key)
    ciphertext = cryptor.encrypt(plaintext)

    print(base64.b64encode(ciphertext).decode('utf-8'))

if __name__ == "__main__":
    main()
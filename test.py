import SAES
import base64

# cryptor = SAES.new('Thats my Kung Fu')
cryptor = SAES.new('Thats my Kung Fu', "Kung Fu Fighting")
ciphertext = cryptor.encrypt('Two One Nine Two')
print("Criptograma:", ciphertext[:len(ciphertext)//2].hex())
# decryptor = SAES.new('Thats my Kung Fu')
decryptor = SAES.new('Thats my Kung Fu', "Kung Fu Fighting")
print(decryptor.decrypt(ciphertext))
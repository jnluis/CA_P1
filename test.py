import SAES
import base64

cryptor = SAES.new('Thats my Kung Fu')
# cryptor = SAES.new('Thats my Kung Fu', "Kung Fu Fighting")
ciphertext = cryptor.encrypt('Two One Nine Two')
print(base64.b64encode(ciphertext).decode('utf-8'))
decryptor = SAES.new('Thats my Kung Fu')
# decryptor = SAES.new('Thats my Kung Fu', "Kung Fu Fighting")
print(decryptor.decrypt(ciphertext))
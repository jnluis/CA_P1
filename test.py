import SAES
import base64

cryptor = SAES.new('Thats my Kung Fu')
ciphertext = cryptor.encrypt('Two One Nine Two')
print(base64.b64encode(ciphertext).decode('utf-8'))
decryptor = SAES.new('Thats my Kung Fu')
print(decryptor.decrypt(ciphertext))
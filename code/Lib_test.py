from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC, DSA

key = RSA.generate(2048)
f = open('mykey.pem', 'wb')
f.write(key.export_key('PEM'))
f.close()

f = open('mykey.pem', 'r')
key = RSA.import_key(f.read())
print(key)
# message = b'blah'
# key = RSA.generate(2048)
# h = SHA256.new(message)
# signature = pkcs1_15.new(key).sign(h)
# print(signature)
#
# try:
#     pkcs1_15.new(key).verify(h, signature)
#     print("The signature is valid.")
# except (ValueError, TypeError) as e:
#     print("The signature is not valid.", e)

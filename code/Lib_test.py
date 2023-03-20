from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC, DSA

key = RSA.generate(2048)
with open('mykey.pem', 'wb') as f:
    f.write(key.export_key('PEM'))

with open('mykey.pem', 'r') as f:
    key = RSA.import_key(f.read())

message = b'blah'
h = SHA256.new(message)
signature = pkcs1_15.new(key).sign(h)
with open('signature.txt', 'wb') as f:
    f.write(signature)

with open('signature.txt', 'rb') as f:
    imp_sign = f.read()

try:
    pkcs1_15.new(key).verify(h, imp_sign)
    print("The signature is valid.")
except (ValueError, TypeError) as e:
    print("The signature is not valid.", e)

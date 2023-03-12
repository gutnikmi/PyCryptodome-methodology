from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC, DSA

import hashlib

# debug modes
# input
# 1 - input from string
# 2 - input from file
inp = 1
# key used
# 1 - input from string
# 2 - input from file
# 3 - input from server
key_used = 1
# hash used
# 1 - SHA256
# 2 - SHA384
# 3 - SHA512
hash_used = 1
# alg used
# 1 - PKCS#1 v1.5
# 2 - PKCS#1 PSS
# 3 - EdDSA
# 4 - DSA and ECDSA
alg_used = 4


# input
if inp == 1:
    message = b'To be signed'
elif inp == 2:
    pass  # TODO
else:
    raise Exception(f"Failed to load input \n")

# key import
if key_used == 1:
    key = RSA.generate(2048)
    key2 = ECC.generate(curve='ed25519') # todo размерность ключей в презентации 8
    key3 = ECC.generate(curve='P-521') #DSA.generate(2048)
elif key_used == 2:
    key = RSA.import_key(open('private_key.der').read())
elif key_used == 3:
    pass  # TODO
else:
    raise Exception(f"Failed to load key \n")

# hash gen
if hash_used == 1:
    h = SHA256.new(message)
elif hash_used == 2:
    h = SHA384.new(message)
elif hash_used == 3:
    h = SHA512.new(message)
else:
    raise Exception(f"Failed to load Hash \n")


# signing
if alg_used == 1:
    signature = pkcs1_15.new(key).sign(h)
elif alg_used == 2:
    signature = pss.new(key).sign(h)
elif alg_used == 3:
    signer = eddsa.new(key2, 'rfc8032')
    signature = signer.sign(message)
elif alg_used == 4:
    signer = DSS.new(key3, 'fips-186-3')
    signature = signer.sign(h)
else:
    raise Exception(f"Failed to load signature algorithm \n")

# verifying
key = key.publickey()
try:
    if alg_used == 1:
        pkcs1_15.new(key).verify(h, signature)
    elif alg_used == 2:
        verifier = pss.new(key)
        verifier.verify(h, signature)
    elif alg_used == 3:
        verifier = eddsa.new(key2, 'rfc8032')
        verifier.verify(message, signature)
    elif alg_used == 4:
        verifier = DSS.new(key3, 'fips-186-3')
        verifier.verify(h, signature)
    else:
        raise Exception(f"Failed to load signature algorithm \n")
    print("The signature is valid.")
except (ValueError, TypeError) as e:
   print("The signature is not valid.", e)

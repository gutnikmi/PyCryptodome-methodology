from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC


def sign_pkcs1(hash_chosen, key_source): #signer for Rsa PKCS#1 v1.5
    keys = {
        'generate': RSA.generate(2048)
    }
    key = keys[key_source]
    hashes = {
        '1': SHA256.new(message),
        '2': SHA384.new(message),
        '3': SHA512.new(message)
    }
    h = hashes[hash_chosen]
    signature = pkcs1_15.new(key).sign(h)
    # print(signature)
    return key, signature


def verify_pkcs1(hash_chosen, key, signature):
    try:
        hashes = {
            '1': SHA256.new(message),
            '2': SHA384.new(message),
            '3': SHA512.new(message)
        }
        h = hashes[hash_chosen]
        key = key.publickey()
        pkcs1_15.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


message = b'To be signed'

if __name__ == "__main__":
    key, signature = sign_pkcs1('1', 'generate')
    verify_pkcs1('1', key, signature)

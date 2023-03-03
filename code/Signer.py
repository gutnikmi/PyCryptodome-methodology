from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC


def sign_pkcs1(hash_chosen, key_source): #signer for Rsa PKCS#1 v1.5
    keys = {
        'generate': RSA.generate(2048)
    }
    key = keys[key_source]
    h = hashes[hash_chosen]
    signature = pkcs1_15.new(key).sign(h)
    # print(signature)
    return key, signature


def verify_pkcs1(hash_chosen, key, signature):
    try:
        h = hashes[hash_chosen]
        key = key.publickey()
        pkcs1_15.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_pss(hash_chosen, key_source): #signer for Rsa PKCS#1 PSS
    keys = {
        'generate': RSA.generate(2048)
    }
    key = keys[key_source]
    h = hashes[hash_chosen]
    signature = pss.new(key).sign(h)
    # print(signature)
    return key, signature


def verify_pss(hash_chosen, key, signature):
    try:
        h = hashes[hash_chosen]
        key = key.publickey()
        pss.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_eddsa(key_source): #signer for Rsa PKCS#1 PSS def sign_eddsa(hash_chosen, key_source):
    keys = {
        'generate_ecc': ECC.generate(curve='ed25519')
    }
    key = keys[key_source]
    h = hashes['3']
    signature = eddsa.new(key, 'rfc8032').sign(h)
    # print(signature)
    return key, signature


def verify_eddsa(key, signature):
    try:
        h = hashes['3']
        key = key.public_key()
        eddsa.new(key, 'rfc8032').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


message = b'To be signed'
hashes = {
    '1': SHA256.new(message),
    '2': SHA384.new(message),
    '3': SHA512.new(message)
}

if __name__ == "__main__":
    a = "2"
    match a:
        case "0":
            key, signature = sign_pkcs1('1', 'generate')
            verify_pkcs1('1', key, signature)
        case "1":
            key, signature = sign_pss('1', 'generate')
            verify_pss('1', key, signature)
        case "2":
            key, signature = sign_eddsa('generate_ecc')
            verify_eddsa(key, signature)

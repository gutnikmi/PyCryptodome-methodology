from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC, DSA


def sign_pkcs1(hash_chosen, key_source, message = b'To be signed'): #signer for Rsa PKCS#1 v1.5
    keys = {
        'generate': RSA.generate(2048)
    }
    key = keys[key_source]
    # print(key.export_key())
    hashes = {
        '1': SHA256.new(message),
        '2': SHA384.new(message),
        '3': SHA512.new(message)
    }
    h = hashes[hash_chosen]
    signature = pkcs1_15.new(key).sign(h)
    # print(signature)
    return key, signature


def verify_pkcs1(hash_chosen, key, signature, message = b'To be signed'):
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


def sign_pss(hash_chosen, key_source, message = b'To be signed'): #signer for Rsa PKCS#1 PSS
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
    signature = pss.new(key).sign(h)
    # print(signature)
    return key, signature


def verify_pss(hash_chosen, key, signature, message = b'To be signed'):
    try:
        hashes = {
            '1': SHA256.new(message),
            '2': SHA384.new(message),
            '3': SHA512.new(message)
        }
        h = hashes[hash_chosen]
        key = key.publickey()
        pss.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_eddsa(key_source, message = b'To be signed'): #signer for eddsa
    keys = {
        'generate': ECC.generate(curve='ed25519')
    }
    key = keys[key_source]
    hashes = {
        '1': SHA256.new(message),
        '2': SHA384.new(message),
        '3': SHA512.new(message)
    }
    h = hashes['3']
    signature = eddsa.new(key, 'rfc8032').sign(h)
    # print(signature)
    return key, signature


def verify_eddsa(key, signature, message = b'To be signed'):
    try:
        hashes = {
            '1': SHA256.new(message),
            '2': SHA384.new(message),
            '3': SHA512.new(message)
        }
        h = hashes['3']
        key = key.public_key()
        eddsa.new(key, 'rfc8032').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_dsa(hash_chosen, key_source, message = b'To be signed'): #signer for dsa
    keys = {
        'generate': DSA.generate(2048)
    }
    hashes = {
        '1': SHA256.new(message),
        '2': SHA384.new(message),
        '3': SHA512.new(message)
    }
    key = keys[key_source]
    h = hashes[hash_chosen]
    signature = DSS.new(key, 'fips-186-3').sign(h)
    # print(key)
    return key, signature


def verify_dsa(hash_chosen, key, signature, message = b'To be signed'):
    try:
        hashes = {
            '1': SHA256.new(message),
            '2': SHA384.new(message),
            '3': SHA512.new(message)
        }
        h = hashes[hash_chosen]
        key = key.public_key()
        DSS.new(key, 'fips-186-3').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_ecdsa(hash_chosen, key_source, message = b'To be signed'): #signer for eddsa
    keys = {
        'generate': ECC.generate(curve='P-521')
    }
    key = keys[key_source]
    hashes = {
        '1': SHA256.new(message),
        '2': SHA384.new(message),
        '3': SHA512.new(message)
    }
    h = hashes[hash_chosen]
    signature = DSS.new(key, 'fips-186-3').sign(h)
    # print(signature)
    return key, signature


def verify_ecdsa(hash_chosen, key, signature, message = b'To be signed'):
    try:
        hashes = {
            '1': SHA256.new(message),
            '2': SHA384.new(message),
            '3': SHA512.new(message)
        }
        h = hashes[hash_chosen]
        key = key.public_key()
        DSS.new(key, 'fips-186-3').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError) as e:
        print("The signature is not valid.", e)


# message = b'To be signed'



if __name__ == "__main__":
    a = "0"
    match a:
        case "0":
            key, signature = sign_pkcs1('1', 'generate')
            verify_pkcs1('1', key, signature)
        case "1":
            key, signature = sign_pss('1', 'generate')
            verify_pss('1', key, signature)
        case "2":
            key, signature = sign_eddsa('generate')
            verify_eddsa(key, signature)
        case "3":
            key, signature = sign_dsa('1', 'generate')
            verify_dsa('1', key, signature)
        case "4":
            key, signature = sign_ecdsa('2', 'generate') # hash only 2 or 3
            verify_ecdsa('2', key, signature)

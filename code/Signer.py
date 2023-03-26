from Crypto.Signature import pkcs1_15, DSS, pss, eddsa
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA, ECC, DSA

hashes = {
        '1': SHA256.new,
        '2': SHA384.new,
        '3': SHA512.new
    }


def import_rsa_v1_5_key():
    with open('RSA v1.5/private_rsa_v1_5.pem', 'r') as f:
        key = RSA.import_key(f.read())
        return key


def generate_rsa_v1_5_key():
    key = RSA.generate(2048)
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('RSA v1.5/private_rsa_v1_5.pem', 'wb') as f:
            f.write(key.export_key('PEM'))
        with open('RSA v1.5/public_rsa_v1_5.pem', 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
    return key


def import_rsa_pss_key():
    with open('RSA PSS/private_rsa_pss.pem', 'r') as f:
        key = RSA.import_key(f.read())
        return key


def generate_rsa_pss_key():
    key = RSA.generate(2048)
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('RSA PSS/private_rsa_pss.pem', 'wb') as f:
            f.write(key.export_key('PEM'))
        with open('RSA PSS/public_rsa_pss.pem', 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
    return key


def import_eddsa_key():
    with open('EdDSA/private_eddsa.pem', 'rt') as f:
        key = ECC.import_key(f.read())
        return key


def generate_eddsa_key():
    key = ECC.generate(curve='ed25519')
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('EdDSA/private_eddsa.pem', 'wt') as f:
            f.write(key.export_key(format='PEM'))
        with open('EdDSA/public_eddsa.pem', 'wt') as f:
            f.write(key.public_key().export_key(format='PEM'))
    return key


def import_pure_eddsa_key():
    with open('PureEdDSA/private_pure_eddsa.pem', 'rt') as f:
        key = ECC.import_key(f.read())
        return key


def generate_pure_eddsa_key():
    key = ECC.generate(curve='ed25519')
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('PureEdDSA/private_pure_eddsa.pem', 'wt') as f:
            f.write(key.export_key(format='PEM'))
        with open('PureEdDSA/public_pure_eddsa.pem', 'wt') as f:
            f.write(key.public_key().export_key(format='PEM'))
    return key


def import_dsa_key():
    with open('DSA/private_dsa.pem', 'rt') as f:
        key = DSA.import_key(f.read())
        return key


def generate_dsa_key():
    key = DSA.generate(2048)
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('DSA/private_dsa.pem', 'wb') as f:
            f.write(key.export_key('PEM'))
        with open('DSA/public_dsa.pem', 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
    return key


def import_ecdsa_key():
    with open('ECDSA/private_ecdsa.pem', 'rt') as f:
        key = ECC.import_key(f.read())
        return key


def generate_ecdsa_key():
    key = ECC.generate(curve='P-521')
    a = input("Would you like to save the key on your device?\n"
              "(Warning! this will erase the previous key of that type in the keys folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('ECDSA/private_ecdsa.pem', 'wt') as f:
            f.write(key.export_key(format='PEM'))
        with open('ECDSA/public_ecdsa.pem', 'wt') as f:
            f.write(key.public_key().export_key(format='PEM'))
    return key


def sign_v1_5(hash_chosen, key_source, message=b'To be signed'):  # signer for Rsa PKCS#1 v1.5
    # print(key_source)
    keys = {
        'generate': generate_rsa_v1_5_key,
        'import': import_rsa_v1_5_key
    }
    key = keys[key_source]()
    h = hashes[hash_chosen](message)
    signature = pkcs1_15.new(key).sign(h)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_v1_5.txt', 'wb') as f:
            f.write(signature)
    return key, signature


def verify_v1_5(hash_chosen, key=None, signature=None, message=b'To be signed'):
    try:
        h = hashes[hash_chosen](message)
        if key is None and signature is None:
            with open('RSA v1.5/public_rsa_v1_5.pem', 'r') as f:
                key = RSA.import_key(f.read())
            with open('Signatures/signature_v1_5.txt', 'rb') as f:
                signature = f.read()
        pkcs1_15.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_pss(hash_chosen, key_source, message=b'To be signed'):  # signer for Rsa PKCS#1 PSS
    keys = {
        'generate': generate_rsa_pss_key,
        'import': import_rsa_pss_key
    }
    key = keys[key_source]()
    h = hashes[hash_chosen](message)
    signature = pss.new(key).sign(h)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_pss.txt', 'wb') as f:
            f.write(signature)
    # print(signature)
    return key, signature


def verify_pss(hash_chosen, key = None, signature = None, message=b'To be signed'):
    try:
        h = hashes[hash_chosen](message)
        if key is None and signature is None:
            with open('RSA PSS/public_rsa_pss.pem', 'r') as f:
                key = RSA.import_key(f.read())
            with open('Signatures/signature_pss.txt', 'rb') as f:
                signature = f.read()
        pss.new(key).verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_eddsa(hash_chosen, key_source, message=b'To be signed'):  # signer for eddsa
    keys = {
        'generate': generate_eddsa_key,
        'import': import_eddsa_key
    }
    key = keys[key_source]()
    h = SHA512.new(message)
    signature = eddsa.new(key, 'rfc8032').sign(h)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_eddsa.txt', 'wb') as f:
            f.write(signature)

    return key, signature


def verify_eddsa(hash_chosen, key = None, signature = None, message=b'To be signed'):
    try:
        h = SHA512.new(message)
        if key is None and signature is None:
            with open('EdDSA/public_eddsa.pem', 'r') as f:
                key = ECC.import_key(f.read())
            with open('Signatures/signature_eddsa.txt', 'rb') as f:
                signature = f.read()
        eddsa.new(key, 'rfc8032').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_pure_eddsa(hash_chosen, key_source, message=b'To be signed'):
    keys = {
        'generate': generate_pure_eddsa_key,
        'import': import_pure_eddsa_key
    }
    key = keys[key_source]()
    signature = eddsa.new(key, 'rfc8032').sign(message)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_pure_eddsa.txt', 'wb') as f:
            f.write(signature)

    return key, signature


def verify_pure_eddsa(hash_chosen, key = None, signature = None, message=b'To be signed'):
    try:
        if key is None and signature is None:
            with open('PureEdDSA/public_pure_eddsa.pem', 'r') as f:
                key = ECC.import_key(f.read())
            with open('Signatures/signature_pure_eddsa.txt', 'rb') as f:
                signature = f.read()
        eddsa.new(key, 'rfc8032').verify(message, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_dsa(hash_chosen, key_source, message=b'To be signed'):  # signer for dsa
    keys = {
        'generate': generate_dsa_key,
        'import': import_dsa_key
    }
    key = keys[key_source]()
    h = hashes[hash_chosen](message)
    signature = DSS.new(key, 'fips-186-3').sign(h)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_dsa.txt', 'wb') as f:
            f.write(signature)
    return key, signature


def verify_dsa(hash_chosen, key=None, signature=None, message=b'To be signed'):
    try:
        h = hashes[hash_chosen](message)
        if key is None and signature is None:
            with open('DSA/public_dsa.pem', 'r') as f:
                key = DSA.import_key(f.read())
            with open('Signatures/signature_dsa.txt', 'rb') as f:
                signature = f.read()
        DSS.new(key, 'fips-186-3').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


def sign_ecdsa(hash_chosen, key_source, message=b'To be signed'):  # signer for eddsa
    keys = {
        'generate': generate_ecdsa_key,
        'import': import_ecdsa_key
    }
    key = keys[key_source]()
    h = hashes[hash_chosen](message)
    signature = DSS.new(key, 'fips-186-3').sign(h)
    a = input("Would you like to save the signature on your device?\n"
              "(Warning! this will erase the previous signature of that type in the signatures folder)\n"
              "press y to save / n to skip\n")
    if a == 'y':
        with open('Signatures/signature_ecdsa.txt', 'wb') as f:
            f.write(signature)
    return key, signature


def verify_ecdsa(hash_chosen, key=None, signature=None, message=b'To be signed'):
    try:
        h = hashes[hash_chosen](message)
        if key is None and signature is None:
            with open('ECDSA/public_ecdsa.pem', 'r') as f:
                key = ECC.import_key(f.read())
            with open('Signatures/signature_ecdsa.txt', 'rb') as f:
                signature = f.read()
        DSS.new(key, 'fips-186-3').verify(h, signature)
        print("The signature is valid.")
    except (ValueError, TypeError) as e:
        print("The signature is not valid.", e)



# message = b'To be signed'


if __name__ == "__main__":
    a = "0"
    match a:
        case "0":
            key, signature = sign_v1_5('1', 'generate')  # import
            verify_v1_5('1', key, signature)  # verify_pkcs1('1', signature, key)
        case "1":
            key, signature = sign_pss('1', 'generate')
            verify_pss('1', key, signature)
        case "2":
            key, signature = sign_eddsa('null', 'generate')  # no hash selection
            verify_eddsa('null', key, signature)
        case "3":
            key, signature = sign_dsa('1', 'generate')
            verify_dsa('1', key, signature)
        case "4":
            key, signature = sign_ecdsa('2', 'generate')
            verify_ecdsa('2', key, signature)
        case "5":
            key, signature = sign_pure_eddsa('null', 'generate')  # no hash selection
            verify_pure_eddsa('null', key, signature)

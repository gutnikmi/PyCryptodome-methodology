from Signer import sign_rsa_v1_5, sign_rsa_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_rsa_v1_5, verify_rsa_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa
import sys

def signer_func(alg, hash_chosen, key_source, message):
    signers = {
        '1': sign_rsa_v1_5,
        '2': sign_rsa_pss,
        '3': sign_dsa,
        '4': sign_ecdsa,
        '5': sign_eddsa,
        '6': sign_pure_eddsa
    }
    return signers[alg](hash_chosen, key_source, message)


def verifier_func(alg, hash_chosen, key, signature, message):
    verifiers = {
        '1': verify_rsa_v1_5,
        '2': verify_rsa_pss,
        '3': verify_dsa,
        '4': verify_ecdsa,
        '5': verify_eddsa,
        '6': verify_pure_eddsa
    }
    return verifiers[alg](hash_chosen, key, signature, message)


if __name__ == "__main__":
    print("What would you like to do? (enter the number of the action without the dot) \n"
          "1.Sign/verify the message \n"
          "2.Choose the signing algorithm \n")

    match input():
        case '1':
            print("Select a Hash algorithm:"
                  " \n1. SHA256"
                  " \n2. SHA384"
                  " \n3. Sha512")
            h = input()
            if h != "1" and h != "2" and h != "3":
                print("Unsupported hash algorithm")
                sys.exit()
            print("Choose the key source:"
                  "\n1. Generate the key"
                  "\n2. Import the key from file")
            s = input()
            if s == "1":
                k = 'generate'
            else:
                if s == "2":
                    k = 'import'
                else:
                    print("Wrong key source")
                    sys.exit()

            print("Enter the message to be signed/verified")
            m = input().encode('utf-8')
            print("Choose an algorithm:"
                  " \n 1. Rsa PKCS#1 v1.5"
                  " \n 2. Rsa PKCS#1 PSS"
                  " \n 3. DSA"
                  " \n 4. ECDSA"
                  " \n 5. HashedEdDSA"
                  " \n 6. PureEdDSA")
            a = input()
            if a != "1" and a != "2" and a != "3" and a != "4" and a != "5":
                print("Unsupported algorithm")
                sys.exit()
            print("Choose action:"
                  "\n1. Sign"
                  "\n2. Verify ")
            act = input()
            if act != '1' and act != '2':
                print("Wrong action")
                sys.exit()
            if act == '1':
                key, signature = signer_func(a, h, k, m)
                if input("Would you like to verify the signature? y/n\n") == 'y':
                    verifier_func(a, h, key, signature, m)  # todo
            if act == '2':
                pass

        case '2':
            pass  # подбор алгоритма
        case _:
            print("Wrong action")
            sys.exit()

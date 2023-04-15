from Signer import sign_rsa_v1_5, sign_rsa_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_rsa_v1_5, verify_rsa_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa
import sys
from Benchmark import bench, show_bench
import os.path


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
    if not (os.path.isfile("Benchmarks\generate.csv") and os.path.isfile("Benchmarks\import.csv")):
        print("No benchmarks have been found, would you like to perform a benchmark?\n"
              "It is recommended to do so as it will automatically create key pares for all signature algorithms\n"
              "Warning! This will overwrite all saved keys and signatures"
              "y/n")
        if input() == 'y':
            bench()

    print("What would you like to do? (enter the number of the action without the dot) \n"
          "1.Sign/verify the message \n"
          "2.Choose the signing algorithm \n")

    match input():
        case '1':
            print("Choose an algorithm:"
                  " \n 1. Rsa PKCS#1 v1.5"
                  " \n 2. Rsa PKCS#1 PSS"
                  " \n 3. DSA"
                  " \n 4. ECDSA"
                  " \n 5. HashedEdDSA"
                  " \n 6. PureEdDSA")
            a = input()
            if a != "1" and a != "2" and a != "3" and a != "4" and a != "5" and a != "6":
                print("Unsupported algorithm")
                sys.exit()
            if a != '5' and a != '6':
                print("Select a Hash algorithm:"
                      " \n1. SHA256"
                      " \n2. SHA384"
                      " \n3. Sha512")
                h = input()
                if h != "1" and h != "2" and h != "3":
                    print("Unsupported hash algorithm")
                    sys.exit()
            else:
                h = None
            print("Enter the message to be signed")
            m = input().encode('utf-8')
            print("Would you like to: \n"
                  "1.Sign\n"
                  "2.Verify\n"
                  "the message?")
            action = input()
            if action == '2':
                try:
                    verifier_func(a, h, None, None, m)
                except Exception as e:
                    print(e)
                    sys.exit()
            elif action == '1':
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
                try:
                    key, signature = signer_func(a, h, k, m)
                except Exception as e:
                    print(e)
                    sys.exit()
                if input("Would you like to verify the signature? y/n\n") == 'y':
                    try:
                        verifier_func(a, h, key, signature, m)
                    except Exception as e:
                        print(e)
                        sys.exit()
                else:
                    print("Wrong action")
                    sys.exit()

        case '2':
            print("Would you like to: \n"
                  "1. Perform/see benchmarks of all available algorithms on this device\n"
                  "2. Get a recommendation for which algorithm to use in yours use case\n")
            b = input()
            if b == '1':
                b_1 = input("Would you like to:\n"
                            "1. Perform a benchmark\n"
                            "2. See previous benchmarks\n")
                if b_1 == '1':
                    bench()
                    print("Would you like to see the results of the benchmark?\n"
                          "y/n\n")
                    if input() == 'y':
                        show_bench()

                elif b_1 == '2':
                    show_bench()
                else:
                    print("Wrong action")
                    sys.exit()
            elif b == '2':
                print("What are you going to use the signature for?"
                      "1. Authentication protocols\n"
                      "2. Certificates\n"
                      "3. Blockchain\n"
                      "4. Documents\n"
                      "5. Message authentication\n")
                match input():
                    case '1':
                        print("Recompounded algorithms: pureEdDSA\n"
                              "Not recommended algorithms: DSA, RSA\n")
                    case '2':
                        print("Recompounded algorithms: DSA RSA EdDSA ECDSA\n"
                              "Not recommended algorithms: - \n")
                    case '3':
                        print("Recompounded algorithms: ECDSA EdDSA\n"
                              "Not recommended algorithms: DSA, RSA, RSA PSS\n")
                    case '4':
                        print("Recompounded algorithms: ECDSA, EdDSA\n"
                              "Not recommended algorithms: DSA, RSA, RSA PSS\n")
                    case '5':
                        print("Recompounded algorithms: pureEdDSA, ECDSA, EdDSA, RSA, RSA PSS\n"
                              "Not recommended algorithms: DSA\n")
                    case _:
                        print("wrong action")
                        sys.exit()
                if input("Would you like to see the benchmark of all supported signature algorithms?\n"
                         "y/n") == 'y':
                    try:
                        show_bench()
                    except Exception as e:
                        print(e)
                        sys.exit()
            else:
                print("Wrong action")
                sys.exit()



        case _:
            print("Wrong action")
            sys.exit()

from Signer import sign_rsa_v1_5, sign_rsa_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_rsa_v1_5, verify_rsa_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa
import time
import csv
from prettytable import from_csv


def bench():
    signers = [sign_rsa_v1_5, sign_rsa_pss, sign_dsa, sign_ecdsa]
    verifiers = [verify_rsa_v1_5, verify_rsa_pss, verify_dsa, verify_ecdsa]
    n_h_s = [sign_eddsa, sign_pure_eddsa]
    n_h_v = [verify_eddsa, verify_pure_eddsa]
    hashes = ['1', '2', '3']
    result = [['algorithm', 'hash', 'sign', 'verify', 'total']]
    alg = []
    modes = ['generate', 'import']
    for mode in modes:
        print("Performing ", mode, "benchamrk")
        for id, sign in enumerate(signers):
            for hash in hashes:
                # print(verifiers[id].__name__.replace('verify_', ""), "with",
                # (lambda hash: "SHA256" if hash == '1' else "SHA384" if hash == '2' else "SHA512")(hash))
                alg.append(verifiers[id].__name__.replace('verify_', ""))
                alg.append((lambda hash: "SHA256" if hash == '1' else "SHA384" if hash == '2' else "SHA512")(hash))
                start_t = time.time()
                sign(hash, mode, b'To be signed', 'm')
                sign_t = time.time() - start_t
                pre_ver = time.time()
                verifiers[id](hash, None, None, b'To be signed', 'm')
                verify_time = time.time() - pre_ver
                total_time = time.time() - start_t
                alg.append(f'{sign_t:.5f}')
                alg.append(f'{verify_time:.5f}')
                alg.append(f'{total_time:.5f}')
                result.append(alg)
                alg = []
                # print("time to sign: ", f'{sign_t:.4f}',
                # "time to verify:", f'{verify_time:.4f}', "time_total:", f'{total_time:.4f}')
        for id, sign in enumerate(n_h_s):
            alg.append(n_h_v[id].__name__.replace('verify_', ""))
            if n_h_v[id].__name__.replace('verify_', "") == 'eddsa':
                alg.append('SHA512')
            else:
                alg.append('-')
            start_t = time.time()
            sign('', mode, b'To be signed', 'm')
            sign_t = time.time() - start_t
            pre_ver = time.time()
            n_h_v[id]('', None, None, b'To be signed', 'm')
            verify_time = time.time() - pre_ver
            total_time = time.time() - start_t
            alg.append(f'{sign_t:.5f}')
            alg.append(f'{verify_time:.5f}')
            alg.append(f'{total_time:.5f}')
            result.append(alg)
            alg = []
        with open('Benchmarks\{0}.csv'.format(mode), 'w', newline='') as myFile:
            writer = csv.writer(myFile, delimiter=';')
            writer.writerows(result)
            result = [['algorithm', 'hash', 'sign', 'verify', 'total']]
            print("done")


def show_bench():
    print("import benchmark")
    with open("Benchmarks\import.csv") as fp:
        table = from_csv(fp)
        print(table)
    print("generate benchmark")
    with open("Benchmarks\generate.csv") as fp:
        table = from_csv(fp)
        print(table)




if __name__ == "__main__":
    # bench()
    show_bench()

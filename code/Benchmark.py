from Signer import sign_rsa_v1_5, sign_rsa_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_rsa_v1_5, verify_rsa_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa
import time

signers = [sign_rsa_v1_5, sign_rsa_pss, sign_dsa, sign_ecdsa]
verifiers = [verify_rsa_v1_5, verify_rsa_pss, verify_dsa, verify_ecdsa]
hashes = ['1', '2', '3']
hash_type = lambda hash: "SHA256" if hash == '1' else "SHA384" if hash == '2' else "SHA512"
for id, sign in enumerate(signers):
    for hash in hashes:
        print(verifiers[id].__name__.replace('verify_', ""), "with", hash_type(hash))
        start_t = time.time()
        sign(hash, 'import', b'To be signed', 'm')
        sign_t = time.time() - start_t
        pre_ver = time.time()
        verifiers[id](hash, None, None, b'To be signed', 'm')
        verify_time = time.time() - pre_ver
        total_time = time.time() - start_t
        print("time to sign: ", f'{sign_t:.4f}', "time to verify:", f'{verify_time:.4f}', "time_total:", f'{total_time:.4f}')

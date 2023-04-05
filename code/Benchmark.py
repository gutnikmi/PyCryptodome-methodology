from Signer import sign_v1_5, sign_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_v1_5, verify_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa
import time

signers = [sign_v1_5, sign_pss, sign_dsa, sign_ecdsa]
verifiers = [verify_v1_5, verify_pss, verify_dsa, verify_ecdsa]
hashes = ['1', '2', '3']

for id, sign in enumerate(signers):
    for hash in hashes:
        print(verifiers[id].__name__, sign.__name__)
        start_t = time.time()
        sign(hash, 'import', b'To be signed', 'm')
        sign_t = time.time() - start_t
        verifiers[id](hash, None, None, b'To be signed', 'm' )
        verify_time = time.time() - sign_t
        total_time = time.time() - start_t
        print("time to sign: ", sign_t, "time to verify:", verify_time, "time_total:", total_time)

from Signer import sign_v1_5, sign_pss, sign_eddsa, sign_dsa, sign_ecdsa, sign_pure_eddsa
from Signer import verify_v1_5, verify_pss, verify_eddsa, verify_dsa, verify_ecdsa, verify_pure_eddsa

signers = [sign_v1_5, sign_pss, sign_dsa, sign_ecdsa]
verifiers = [verify_v1_5, verify_pss, verify_dsa, verify_ecdsa]

for id, sign in enumerate(signers):
    print(verifiers[id], sign)
    sign('1', 'import', b'sign me', 'm')
    verifiers[id]('1')


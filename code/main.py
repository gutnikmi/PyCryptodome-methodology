from Signer import sign_pkcs1, sign_pss, sign_eddsa, sign_dsa, sign_ecdsa
from Signer import verify_pkcs1, verify_pss, verify_eddsa, verify_dsa, verify_ecdsa


def signer_func(alg, hash_chosen, key_source, message):
    signers = {
        '0': sign_pkcs1,
        '1': sign_pss,
        '2': sign_eddsa,
        '3': sign_dsa,
        '4': sign_ecdsa
    }
    return signers[alg](hash_chosen, key_source, message)


if __name__ == "__main__":
    print("Что вы хотите сделать? (введите номер варианта без точки) \n")
    print("1. Подписать/проверить сообщение \n")
    print("2. Подобрать алгоритм подписи \n")

    match input():
        case '1':
            print("Выберите алгоритм:"
                  " \n 1. Rsa PKCS#1 v1.5"
                  " \n 2. Rsa PKCS#1 PSS"
                  " \n 3. EdDSA"
                  " \n 4. DSA"
                  " \n 5. ECDSA")
            match input():
                case '1':  # Rsa PKCS#1 v1.5"
                    print("Введите 1 чтобы подписать и 2 чтобы проверить подпись")
                    if input() == '1':  # sign
                        print("Выберите Хэш:"
                              " \n 1. SHA256"
                              " \n 2. SHA384"
                              " \n 3. Sha512")
                        h = input()
                        print("Выберите источник ключа:"
                              "1. Сгенерировать ключ"
                              "2. Вставить в консоль"
                              "3. Импорт из файла")


                    else:
                        if input() == '2':  # verify
                            print("Выберите Хэш:"
                                  " \n 1. SHA256"
                                  " \n 2. SHA384"
                                  " \n 3. Sha512")
                            h = input()
        case'2':
            pass


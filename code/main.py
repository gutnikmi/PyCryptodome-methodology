from Signer import sign_pkcs1, sign_pss, sign_eddsa, sign_dsa, sign_ecdsa
from Signer import verify_pkcs1, verify_pss, verify_eddsa, verify_dsa, verify_ecdsa
import sys


def signer_func(alg, hash_chosen, key_source, message):
    signers = {
        '1': sign_pkcs1,
        '2': sign_pss,
        '3': sign_eddsa,
        '4': sign_dsa,
        '5': sign_ecdsa
    }
    return signers[alg](hash_chosen, key_source, message)


if __name__ == "__main__":
    print("Что вы хотите сделать? (введите номер варианта без точки) \n")
    print("1. Подписать/проверить сообщение \n")
    print("2. Подобрать алгоритм подписи \n")

    match input():
        case '1':
            print("Выберите Хэш:"
                  " \n1. SHA256"
                  " \n2. SHA384"
                  " \n3. Sha512")
            h = input()
            if h != "1" and h != "2" and h != "3":
                print("Неправильный Хэш")
                sys.exit()
            print("Выберите источник ключа:"
                  "\n1. Сгенерировать ключ"
                  "\n2. Вставить в консоль"
                  "\n3. Импорт из файла")
            s = input()
            if s == "1":
                k = 'generate'
            else:
                if s == "2":
                    k = 'import'
                else:
                    print("Неправильный источник ключа")
                    sys.exit()

            print("Введите сообщение которое необходимо подписать/проверить подпись")
            m = input().encode('utf-8')
            print("Выберите алгоритм:"
                  " \n 1. Rsa PKCS#1 v1.5"
                  " \n 2. Rsa PKCS#1 PSS"
                  " \n 3. EdDSA"
                  " \n 4. DSA"
                  " \n 5. ECDSA")
            a = input()
            if a != "1" and a != "2" and a != "3" and a != "4" and a != "5":
                print("Неподдерживаемый алгоритм")
                sys.exit()
            print("Выберите действие:"
                  "\n1. Подписать"
                  "\n2. Проверить подпись ")
            act = input()
            if act != '1' and act != '2':
                print("Неправильное действие")
                sys.exit()
            if act == '1':
                print(signer_func(a, h, k, m))
            if act == '2':
                pass

        case '2':
            pass  # подбор алгоритма
        case _:
            print("Неправильное действие")
            sys.exit()

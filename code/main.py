
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
                case '1':
                    pass
        case'2':
            pass


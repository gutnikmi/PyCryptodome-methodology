
def func():
    global a
    a+=1


if __name__ == '__main__':
    a = 3
    func()
    print(a)

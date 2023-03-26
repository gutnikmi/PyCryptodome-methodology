def func_a():
    print("god")

def func_b():
    print("dog")


dict1 = {
    '1': func_a,
    '2': func_b
}
a = input()
dict1[a]()




numbers = []
subnums = []
for num in range(0, 10):
    subnums.append(num)
    subnums.append(num + 1)
    subnums.append(num + 2)
    numbers.append(subnums)
    subnums = []
print(numbers)

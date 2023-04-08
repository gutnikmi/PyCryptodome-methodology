import csv
data = [["num1", "num2", "num3"]]
numbers = []
subnums = []
with open('test.csv', 'w', newline='') as myFile:
    writer = csv.writer(myFile, delimiter=';')
    writer.writerows(data)
    for num in range(0, 10):
        subnums.append(num)
        subnums.append(num + 1)
        subnums.append(num + 2)
        numbers.append(subnums)
        subnums = []
    print(numbers)
    writer.writerows(numbers)

print("Writing complete")






with open('test.csv', newline='', encoding="Windows-1251") as File:
    reader = csv.reader(File, delimiter=';')
    for row in reader:
        # if row[0]=='4':
        #     print(row)
        print(row)


# with open('test.csv') as csvfile:
#     reader = csv.DictReader(csvfile, delimiter=';')
#     for row in reader:
#              print(row['num2'])


# results = []
# with open('test.csv') as File:
#     reader = csv.DictReader(File, delimiter=';')
#     for row in reader:
#         results.append(row)
#     for result in results:
#         # if result['num1'] == '5':
#         #     print(result, '\n')
#         print(result)

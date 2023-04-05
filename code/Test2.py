import time

a = time.time()
time.sleep(1)
b = time.time() - a
print(f'{b:.4f}')

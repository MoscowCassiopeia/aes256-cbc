# aes256-cbc
#### Crypt and decrypt files
Класс обертка над пакетом `cryptography`
позволяет шифровать и расшифровывать файлы,
алгоритмом `AES256-CBC`

Example:
```python
import aes_cls
from aes_cls import sha256sum

aes = ChipherAES(passwd='Clear text'.encode(), iterations=2018)

aes.encrypt('source.txt', 'source.enc')
aes.decrypt('source.enc', 'decrypt.txt')

if sha256sum('source.txt') == sha256sum('decrypt.txt'):
    print('ok')
else:
    print('bad')
```

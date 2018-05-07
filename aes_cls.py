'''
Класс обертка над пакетом cryptography
позволяет шифровать и расшифровывать файлы,
алгоритмом AES256-CBC
'''
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

class ChipherAES:
    '''
    Шифрует - Дешифрует файлы,
    алгоритмом AES256-CBC
    Ключ из пароля готовится функцией PBKDF2
    passwd - пароль, строка байт
    iv - вектор инициализации, если не указан, генерится os.urandom(16)
    hash_name - алгоритм хеша который используется в PBKDF2
    salt - соль для PBKDF2, если не указана, используем дефолтную соль
    iterations - кол-во итераций для PBKDF2
    chunk_size - размер блока которым читаем файл, дефолт 8192
    '''
    def __init__(self, passwd, iv=None, hash_name='sha256',
                 salt=None, iterations=None, chunk_size=8192):

        if not isinstance(passwd, bytes):
            raise Exception('passwd must be bytes')
        if len(passwd) < 6:
            raise Exception('passwd min 6 character')
        if salt is not None and not isinstance(salt, bytes):
            raise Exception('salt must be bytes')
        if not hash_name in ('sha256', 'sha1'):
            raise Exception('hash_name must be sha1 or sha256')        
                
        self.passwd = passwd        
        
        # вектор инициализации не указан,
        # генерим его сами
        if iv: self.iv = iv            
        else: self.iv = os.urandom(16)
        
        #тип хеша, для функции PBKDF2
        self.hash_name = hash_name        

        # если соль не указали явно, то используем заранее сгенерированную длиной 128
        if salt:
            self.salt = salt
        else:
            self.salt = b'\xfe]\xe9\x98\x94]\x82\xe3\xaa\x03!\x93D\x05\xd70\x98|\xfaj\xa6\x964a\xd2}k\x00\xe3\x86H%T\x19w/C\xdd|\xec\xe1\xa6\x1a\xab\x10\xf6\xcf\xb21\xd4uzR\x90\x1a/\xd7`QMK\xe4\x06\xa8)\r\xa9\xf1\\\xf3\xc83T\x83\x14\t@4\xbeG\n\x0e\xb27\xad4&\x1ceA3\xe0\xc1\xec\xa5\xa4\xdc\xfd\xf9\x81\r\xd6\x8a+p\xdd\xd2\xd5\xd74\xff\xc8>\xdc{\tx\xeb\xc1,\x10\xc5\xb0G\x06\x92\xc1\x89'

        # если кол-во итераций не указано,
        # используем дефолтное значение прибавляя к нему первый байт пароля
        if iterations is None:            
            self._iterations = 7896 + passwd[0]
        else:
            self._iterations = iterations

        self._dklen = 32
        self._chunk_size = chunk_size   
        self._key = self._pbkdf2()
        self._backend = default_backend()


    def _pbkdf2(self):
        '''
        Подготовка ключа для шифрования
        '''        
        return hashlib.pbkdf2_hmac(self.hash_name,
                                   self.passwd,
                                   self.salt,
                                   self._iterations,
                                   self._dklen)        
    
    def encrypt(self, src_path, dst_path):
        '''
        шифрование файла
        '''
        pad = padding.PKCS7(self._dklen*8).padder()
        alg = algorithms.AES(self._key)
        mode = modes.CBC(self.iv)
        cipher = Cipher(alg, mode, backend=self._backend)
        encryptor = cipher.encryptor()        

        with open(src_path, 'rb') as src_f:
            with open(dst_path, 'wb') as dst_f:
                while True:
                    chunk = src_f.read(self._chunk_size)
                    # если курсор файла равен размеру файла,
                    # значит это последний чанк, производим финализацию паддинга и шифрования                  
                    if src_f.tell() == os.path.getsize(src_path):
                        ptext = pad.update(chunk) + pad.finalize()                                                
                        ctext = encryptor.update(ptext)
                        ctext += encryptor.finalize()                           
                        dst_f.write(ctext)
                        break
                    else:
                        ctext = encryptor.update(chunk)
                        dst_f.write(ctext)
                        

    def decrypt(self, src_path, dst_path):
        '''
        дешифровка файла
        '''
        upad = padding.PKCS7(self._dklen*8).unpadder()
        alg = algorithms.AES(self._key)
        mode = modes.CBC(self.iv)
        cipher = Cipher(alg, mode, backend=self._backend)
        decryptor = cipher.decryptor()        

        with open(src_path, 'rb') as src_f:            
            with open(dst_path, 'wb') as dst_f:
                while True:
                    chunk = src_f.read(self._chunk_size)                    
                    # если курсор файла равен размеру файла,
                    # значит это последний чанк, производим финализацию паддинга и дешифрования                        
                    if src_f.tell() == os.path.getsize(src_path):                                            
                        ptext = decryptor.update(chunk) + decryptor.finalize()                        
                        ptext = upad.update(ptext) + upad.finalize()                        
                        dst_f.write(ptext)
                        break                         
                    else:
                        ptext = decryptor.update(chunk)
                        dst_f.write(ptext)                     


def sha256sum(path):
    '''
    Считает sha256 файла
    '''
    chunk_size = 8192
    hs = hashlib.sha256()    
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            hs.update(chunk)
    return hs.hexdigest()


if __name__ == '__main__':
    aes = ChipherAES(passwd='Долой Царя'.encode(), iterations=2018)
    aes.encrypt('source.txt', 'source.enc')
    aes.decrypt('source.enc', 'decrypt.txt')

    if sha256sum('source.txt') == sha256sum('decrypt.txt'):
        print('ok')
    else:
        print('bad')
        
    
    

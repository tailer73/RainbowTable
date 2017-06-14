#Для использования HMAC
import hmac
from binascii import a2b_hex, b2a_hex, hexlify
#Для подсчета PMK
from hashlib import pbkdf2_hmac, sha1, md5


"""Возвращает хэш WPA/WPA2 пароля. В качестве параметров принимает 2 строки: пароль и ssid"""
def GetWpaHash(password, ssid):
    """sha1 - алгоритм хеширования; 4096 - количество итераций hmac, 32 - размер хеша в байтах"""
    WPAhash = pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 32)
    return hexlify(WPAhash) #вернули хеш как 16-ричное число

#Псевдо-рандомная функция для подсчета PTK
#key:       PMK(то, что хешируется и хранитсяв файле - высчитывается из ssid и пароля)
#A:         b'Pairwise key expansion' - фраза из стандарта подсчета PMK
#B:         apMac, cliMac, aNonce, и sNonce связанные конкантенацией в виде
#           mac1 mac2 nonce1 nonce2, при этом mac1 < mac2 and nonce1 < nonce2
#return:    Возвращает PTK
def PRF(key, A, B):
    #Количество байт в PTK
    nByte = 64
    i = 0
    R = b''#результирующая строка
    #цикл для подсчета PTK
    while(i <= 4):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]

#Возвращает параметры для генерации PTK
#aNonce:        nonce от access point из хэндшейка
#sNonce:        nonce от station из хендшейка
#apMac:         MAC-адрес access point
#cliMac:        MAC-адрес клиента
#return:        (A, B) параметры для генерации PTK
def MakeAB(aNonce, sNonce, apMac, cliMac):
    A = b"Pairwise key expansion"
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    return (A, B)

#Считаем MIC для сообщений рукопожатий
#pmk         pmk(хеш из ssid и пароля)
#A, B:       параметры для подсчета ptk из функции MakeAB
#data:      Список 802.1x кадров с обнуленным полем MIC
#wpa        wpa1 использует hmac c md5, wpa2 использует hmac с sha1. Передать True,
#           если используется wpa1, False - в противном случае
#return:    Список mic для каждого кадра (их обычно 3). Достаточно проверки одного
def MakeMIC(pmk, A, B, data, wpa = False):
    #считаем ptk
    ptk = PRF(pmk, A, B)

    #определяем функцию хеширования
    hmacFunc = md5 if wpa else sha1
    #Создаем список mic
    mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
    return mics






import hmac
import os
import time
from binascii import a2b_hex, b2a_hex, hexlify
from hashlib import pbkdf2_hmac, sha1, md5
from scapy.all import *
import pymysql.cursors

class RainbowTable:
    """Возвращает хэш WPA/WPA2 пароля. В качестве параметров принимает 2 строки: пароль и ssid"""

    @staticmethod
    def __get_wpa_hash(password, ssid):
        wpa_hash = pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 32)
        return hexlify(wpa_hash)

    """Получает на вход имя файла-словаря, ssid как строку.
     Для фиксированного ssid записывает в    выходной файл хеш паролей из словаря.
      Возвращает True в случае успеха и False в обратном случае"""

    @staticmethod
    def __calculate_hash(input_file_name, ssid, connection):
        try:
            input_file = open(input_file_name, 'r')
        except FileNotFoundError:
            return False
        with connection.cursor() as cursor:#create table for 1 ssid
            sql = 'CREATE TABLE hash_' + ssid + ' (hash VARCHAR(64))'
            cursor.execute(sql)
        connection.commit()
        for line in input_file:
            if line[-1] == '\n':
                line = line[:-1]
            # запись в файл хешей
            with connection.cursor() as cursor:
                sql = "INSERT INTO `hash_" + ssid + "`"  + " (`hash`) VALUES (%s)"
                #cursor.execute(sql, ('asd'))
                cursor.execute(sql, (RainbowTable.__get_wpa_hash(line, ssid).decode()))
            connection.commit()
        input_file.close()
        return True

    """create table with passwords from our file with passwords"""

    @staticmethod
    def __write_passwords(pswd_filename, connection):
        try:
            pswd_file = open(pswd_filename, 'r')
        except FileNotFoundError:
            return False
        with connection.cursor() as cursor:
            sql = 'CREATE TABLE passwords (ID MEDIUMINT AUTO_INCREMENT, password VARCHAR(255), PRIMARY KEY (ID))'
            cursor.execute(sql)
        connection.commit()
        with connection.cursor() as cursor:
            sql = "INSERT INTO `passwords` (`password`) VALUES (%s)"
            for line in pswd_file:
                if line[-1] == '\n':
                    line = line[:-1]
                cursor.execute(sql, (line))
        connection.commit()
        pswd_file.close()
        return True

    """На вход поступает файл с паролями, файл с ssid, папка, в которую будут записаны хеши. Если указанной
    папки нет, она создается. Для каждого ssid в папке создается файл с именем hash_ + ssid, в который помещаюся
    все хеши для данного ssid и каждого пароля."""
    @staticmethod
    def create_tables(password_filename, ssid_filename):
        try:
            ssid_file = open(ssid_filename, 'r')
        except FileNotFoundError:
            return False
        connection = pymysql.connect(host='localhost',
                                     user='',
                                     password='',
                                     db='',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        RainbowTable.__write_passwords(password_filename, connection)
        for ssid in ssid_file:  # для каждого ssid создаем файл с именем hash_"имя ssid" и записываем туда хеши
            if ssid[-1] == '\n':
                ssid = ssid[:-1]
            RainbowTable.__calculate_hash(password_filename, ssid, connection)
        ssid_file.close()
        connection.close()
        return True

    # Псевдо-рандомная функция для подсчета PTK
    # key:       PMK(то, что хешируется и хранитсяв файле - высчитывается из ssid и пароля)
    # A:         b'Pairwise key expansion' - фраза из стандарта подсчета PMK
    # B:         apMac, cliMac, aNonce, и sNonce связанные конкантенацией в виде
    #           mac1 mac2 nonce1 nonce2, при этом mac1 < mac2 and nonce1 < nonce2
    # return:    Возвращает PTK
    @staticmethod
    def __pseudo_random_func(key, A, B):
        # Количество байт в PTK
        number_of_bytes = 64
        i = 0
        R = b''  # результирующая строка
        while (i <= 4):
            hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
            R = R + hmacsha1.digest()
            i += 1
        return R[0:number_of_bytes]

    # Возвращает параметры для генерации PTK
    # aNonce:        nonce от access point из хэндшейка
    # sNonce:        nonce от station из хендшейка
    # apMac:         MAC-адрес access point
    # cliMac:        MAC-адрес клиента
    # return:        (A, B) параметры для генерации PTK
    @staticmethod
    def __make_parametres(ap_nonce, sta_once, ap_mac, sta_mac):
        A = b"Pairwise key expansion"
        B = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + min(ap_nonce, sta_once) + max(ap_nonce, sta_once)
        return A, B

    # Считаем MIC для сообщений рукопожатий
    # pmk         pmk(хеш из ssid и пароля)
    # A, B:       параметры для подсчета ptk из функции __make_parametres
    # data:      Список 802.1x кадров с обнуленным полем MIC
    # wpa        wpa1 использует hmac c md5, wpa2 использует hmac с sha1. Передать True,
    #           если используется wpa1, False - в противном случае
    # return:    Список mic для каждого кадра (их обычно 3). Достаточно проверки одного
    @staticmethod
    def __make_mic(pmk, A, B, data, wpa=False):
        # считаем ptk
        ptk = RainbowTable.__pseudo_random_func(pmk, A, B)
        # определяем функцию хеширования
        hmac_func = md5 if wpa else sha1
        mics = [hmac.new(ptk[0:16], i, hmac_func).digest() for i in data]
        return mics

    """На вход функции поступает имя pcap-файла, в котором содержатся сообщения рукопожатий
    Возвращает 2 мак-адреса в 16-ричном виде, 3 key nonce(используются в дальнейшем
    2), 3 поля mic(в дальнейшем используется первое), 3 пакета с обнуленным mic(в дальнейшем используется
    первый). Избыточность объясняется возможной проверкой всех возвращаемых данных """

    @staticmethod
    def __parse_pcap_file(pcap_filename):
        myreader = PcapReader(pcap_filename)  # открываем pcap-файл
        packet_number = 1  # номер текущего сообщения в хэндшейках
        nonces = []  # список nonce, который вернет функция
        mics = []  # список mic, который вернет функция
        data_eapol = []  # список данных с обнуленным полем mic, которые вернет функция
        version = 0
        for packet in myreader:  # пробегаясь по каждому пакету в pcap-файле
            if packet.haslayer(EAPOL) and packet_number == 1:  # определяем, является ли пакет EAPOL
                # и является ли он первым из всех пакетов рукопожатий

                source_addr = packet.addr2.split(':')
                source_addr = ''.join(source_addr)
                dest_addr = packet.addr1.split(':')
                dest_addr = ''.join(dest_addr)
                data = bytes(packet.getlayer(EAPOL))  # данные первого пакета EAPOL
                version = data[6] & 7  # поле версии (1 если wpa1)
                nonce = data[17:49]  # key nonce
                nonces.append(nonce)  # добавляем в список
                packet_number += 1
                continue
            if packet.haslayer(EAPOL) and (packet_number == 2 or packet_number == 3):  # разбор 2 и 3 хендшейка
                len = packet.getlayer(EAPOL).len
                data = bytes(packet.getlayer(EAPOL))[:len + 4]  # достаем данные EAPOL(+4 - длина заголовка)
                nonce = data[17:49]  # key nonce
                mic = data[81:97]  # mic
                nonces.append(nonce)
                mics.append(mic)
                data = list(data)  # в следующих 5 строчках в данных EAPOL обнуляется MIC и данные добавляются в список
                for i in range(16):
                    data[81 + i] = 0x00
                data = bytes(data)
                data_eapol.append(data)
                packet_number += 1
                continue
            # разбор 4 хендшейка аналогично 2 и 3, но без доставания поля Key Nonce
            if packet.haslayer(EAPOL) and packet_number == 4:
                data = bytes(packet.getlayer(EAPOL))
                mic = data[81:97]
                mics.append(mic)
                data = list(data)
                for i in range(16):
                    data[81 + i] = 0x00
                data = bytes(data)
                data_eapol.append(data)
            if (version == 1):  # определяем версию wpa
                is_wpa1 = True
            else:
                is_wpa1 = False
        return a2b_hex(source_addr), a2b_hex(dest_addr), nonces, mics, data_eapol, is_wpa1

    #возврщает пароль по номеру строки
    @staticmethod
    def __get_passwd_for_line(id, connection):
        with connection.cursor() as cursor:
            sql = "SELECT `password` FROM `passwords` WHERE `ID`=%s"
            cursor.execute(sql,(id))
            for row in cursor:
                return row




    # функция для подбора пароля
    # аргументы:
    # pcapf - имя с 4-мя упорядоченными хендшейками
    # ssidName - имя сети\
    # возвращает пароль в случае нахождения
    @staticmethod
    def get_passwd(pcapf, ssid_name):
        source_addr, dest_addr, nonces, mics_from_pcap, data, is_wpa1 = RainbowTable.__parse_pcap_file(pcapf)

        A, B = RainbowTable.__make_parametres(nonces[0], nonces[1], source_addr,
                                              dest_addr)  # получаем значения A и B для генерации PTK (см описание MakeAB)
        id = 0

        connection = pymysql.connect(host='localhost',
                                     user='',
                                     password='',
                                     db='',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        with connection.cursor() as cursor:
            sql = "SELECT `hash` FROM `hash_" + ssid_name + "`"
            cursor.execute(sql)


            for hash in cursor:
                pmk = a2b_hex(hash['hash'])
                mics = RainbowTable.__make_mic(pmk, A, B, data, is_wpa1)
                # если посчитанный mic (первый) совпадает с mic из pcap-файла - пароль найден
                if (b2a_hex(mics[0]).decode().upper()[:-8] == b2a_hex(mics_from_pcap[0]).upper().decode()):
                    passw = RainbowTable.__get_passwd_for_line(id+1, connection)
                    connection.close()
                    return passw['password']
                id += 1
        connection.close()
        return ''

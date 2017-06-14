from ParsingPackets import GetInfoFromPcap
from PTKandMICcalculating import MakeMIC, MakeAB
from wpa import  GetWpaHash, MakeWpaHashesAndWriteInFileForFileWithSSIDsAndOneFileWithPasswords
from binascii import a2b_hex, b2a_hex
import os
import  sys

def Help():
    helpstr = '''Если Вы хотите создать таблицу по файлу из паролей и ssid, введите
    следующие параметры:
    -ssidf имя файла с ssid
    -dictf имя файла-словаря
    -outdir имя файла выходной директории (пустой)
Если Вы хотите найти пароль по таблице, введите следующие параметры:
    -pcap имя файла с beacon frame и 4-мя handshakes
    -inputdir имя директории с таблицами '''
    print(helpstr)

def GetPasswordForLineId(inputdir, id):
    try:  # попытка открыть файл с ssid
        fileWithPasswords = open(inputdir + '/passwords', 'r')
    except FileNotFoundError:  # в случае исключения возвращает пустую строку и выводит соответствующее сообщение
        print("ошибка с файлом passwords\n")
        fileWithPasswords.close()
        return ''
    i = 0
    for line in fileWithPasswords:#пробегаемся по всем паролям и возвращаем с нужным id
        if i == id:
            return line
        else:
            i += 1


def main():
    #поля для дальнейшей работы
    wpa1 = True #true - если используется wpa1
    ssidf = '' #файл со всеми ssid
    dictf = '' #файл со всеми паролями
    outdir = '' #папка для хранения таблиц
    pcapf = '' #pcap-файл с хендшейками
    inputdir = '' #папка с таблицами, по которым будет произведена атака
    if len(sys.argv) == 1:
        Help()#если аргуметов нет - выводим help-сообщение
        return
    for i in range(len(sys.argv)):#заполняем переменные значениями аргументов
        if sys.argv[i] == '-h' or sys.argv[i] == '-help':
            Help()
            return
        if sys.argv[i] == '-ssidf':
            ssidf = sys.argv[i+1]
        if sys.argv[i] == '-dictf':
            dictf = sys.argv[i + 1]
        if sys.argv[i] == '-outdir':
            outdir = sys.argv[i + 1]
        if sys.argv[i] == '-pcap':
            pcapf = sys.argv[i + 1]
        if sys.argv[i] == '-inputdir':
            inputdir = sys.argv[i + 1]
    if not (ssidf == '') and not (dictf == '') and not (outdir == ''): #если все 3 переменные заполнены
        #заполняем папку таблицами: для каждого ssid - все пароли из словаря
        MakeWpaHashesAndWriteInFileForFileWithSSIDsAndOneFileWithPasswords(dictf, ssidf, outdir)

    if not (pcapf == '') and not (inputdir == ''): #если заполнены поля с pcap-файлом и папкой с таблицами
        ssid, sAddr, dAddr, nonces, micsFromPcap, data, isWpa1 = GetInfoFromPcap(pcapf)

        try:  # попытка открыть файл с ssid
            fileWithSSIDs = open(inputdir+ '/hash_' + ssid, 'r')
        except FileNotFoundError:  # в случае исключения возвращает False и выводит соответствующее сообщение
            print("Ну существует такого ssid в таблице\n")
            return
        A, B = MakeAB(nonces[0], nonces[1], sAddr, dAddr)#получаем значения A и B для генерации PTK (см описание MakeAB)
        id = 0
        for hash in fileWithSSIDs:#пробегаемся по каждому хешу в папке
            if hash[-1] == '\n':
                hash = hash[:-1]
            pmk = a2b_hex(hash)#записываем pmk без \n
            mics = MakeMIC(pmk, A, B, data, isWpa1) #считаем MIC
            #если посчитанный mic (первый) совпадает с mic из pcap-файла - пароль найден
            if (b2a_hex(mics[0]).decode().upper()[:-8] == b2a_hex(micsFromPcap[0]).upper().decode()):
                print('password is: ' + GetPasswordForLineId(inputdir, id))#смотрим номер пароля в файле с паролями
                return
            id += 1




main()

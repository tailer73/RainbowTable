import hashlib, binascii, hmac
import os
#В файле описаны функции хеширования (составления PSK)
"""Возвращает хэш WPA/WPA2 пароля. В качестве параметров принимает 2 строки: пароль и ssid"""
def GetWpaHash(password, ssid):
    """sha1 - алгоритм хеширования; 4096 - количество итераций hmac, 32 - размер хеша в байтах"""
    WPAhash = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 32)
    return binascii.hexlify(WPAhash) #вернули хеш как 16-ричное число


"""Получает на вход имя файла-словаря, ssid как строку, имя выходного файла. Для фиксированного ssid записывает в
выходной файл хеш паролей из словаря. Возвращает True в случае успеха и False в обратном случае"""
def MakeWpaHashesAndWriteInFileForOneSSIDAndOneFileWithPasswords(inputFileName, ssid, outputFileName):
    try: #попытка открыть входной файл
        inputFile = open(inputFileName, 'r')
    except FileNotFoundError:#вывод сообщения и возврат False в случае неудачи
        print("There no such input file\n")
        return False
    outputFile = open(outputFileName, 'w')#открытие файла на запись
    for line in inputFile:
        if line[-1] == '\n':
            line = line[:-1]
        #запись в файл хешей
        outputFile.write(GetWpaHash(line, ssid).decode() + "\n")
    inputFile.close() #закртыие файлов
    outputFile.close()
    return True


"""Добавляет содержимое первого файла в конец второго. Используется для создания общего словаря паролей"""
def WriteFileToTheEndOfAnother(firstFileName, secondFileName):
    try:
        firstFile = open(firstFileName, 'r')
    except FileNotFoundError:
        print("Error with file open\n")
        return False
    secondFile = open(secondFileName, 'a')
    secondFile.write(firstFile.read())
    secondFile.close()
    firstFile.close()
    return True

"""На вход поступает файл с паролями, файл с ssid, папка, в которую будут записаны хеши. Если указанной
папки нет, она создается. Для каждого ssid в папке создается файл с именем hash_ + ssid, в который помещаюся
все хеши для данного ssid и каждого пароля. Все пароли хранятся в файле passwords"""
def MakeWpaHashesAndWriteInFileForFileWithSSIDsAndOneFileWithPasswords(inputFileNameWithPasswords,
                                                                       inputFileNameWithSSIDs, outputDirectoryName):
    try:#попытка открыть файл с ssid
        fileWithSSIDs = open(inputFileNameWithSSIDs, 'r')
    except FileNotFoundError:# в случае исключения возвращает False и выводит соответствующее сообщение
        print("Error with SSID file\n")
        return False
    if not os.path.exists(outputDirectoryName): #если папка не существует, создаем ее
        os.makedirs(outputDirectoryName)
    else:
        if os.listdir(outputDirectoryName):#папка должна быть пуста
            print('Directory is not empty\n')
            return  False
    fileWirhPasswordsName = outputDirectoryName + "/" + "passwords"
    WriteFileToTheEndOfAnother(inputFileNameWithPasswords, fileWirhPasswordsName)
    for ssid in fileWithSSIDs: #для каждого ssid создаем файл с именем hash_"имя ssid" и записываем туда хеши
        if ssid[-1] == '\n':
            ssid = ssid[:-1]
        outputFileName = outputDirectoryName + "/"  "hash" + "_" + ssid
        MakeWpaHashesAndWriteInFileForOneSSIDAndOneFileWithPasswords(inputFileNameWithPasswords, ssid, outputFileName)
    fileWithSSIDs.close()
    return True

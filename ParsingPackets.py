import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from binascii import a2b_hex


"""На вход функции поступает имя pcap-файла, в котором содержатся сообщения рукопожатий
и минимум один beacon frame от точки нужной сети. Beacon frame сети, на которую проводится атака
должен быть последним среди всех beacon frame!!!
Возвращает ssid сети, 2 мак-адреса в 16-ричном виде, 3 key nonce(используются в дальнейшем
2), 3 поля mic(в дальнейшем используется первое), 3 пакета с обнуленным mic(в дальнейшем используется
первый). Избыточность объясняется возможной проверкой всех возвращаемых данных """
def GetInfoFromPcap(pcapFileName):
    myreader = PcapReader(pcapFileName)#открываем pcap-файл
    packetNumber = 1#номер текущего сообщения в хэндшейках
    nonces = []#список nonce, который вернет функция
    mics = [] #список mic, который вернет функция
    dataEapol = [] #список данных с обнуленным полем mic, которые вернет функция
    version = 0
    for packet in myreader:#пробегаясь по каждому пакету в pcap-файле
        if packet.haslayer(EAPOL) and packetNumber == 1:#определяем, является ли пакет EAPOL
            #и является ли он первым из всех пакетов рукопожатий

            sAddr = packet.addr2.split(':')
            sAddr = ''.join(sAddr) #адрес источника как строка байт без разделителей
            dAddr = packet.addr1.split(':')
            dAddr = ''.join(dAddr) #адрес получателя как строка байт без разделителей
            data = bytes(packet.getlayer(EAPOL)) #данные первого пакета EAPOL
            version = data[6] & 7 #поле версии (1 если wpa1)
            nonce = data[17:49] #key nonce
            nonces.append(nonce)#добавляем в список
            packetNumber += 1 #следующий пакет для обработки - второй
            continue
        if packet.haslayer(EAPOL) and (packetNumber == 2 or packetNumber == 3):#разбор 2 и 3 хендшейка
            len = packet.getlayer(EAPOL).len #узнаем длину пакета EAPOL
            data = bytes(packet.getlayer(EAPOL))[:len+4] #достаем данные EAPOL(+4 - длина заголовка)
            nonce = data[17:49] # key nonce
            mic = data[81:97] #mic
            nonces.append(nonce)
            mics.append(mic)
            data = list(data) #в следующих 5 строчках в данных EAPOL обнуляется MIC и данные добавляются в список
            for i in range(16):
                data[81+i] = 0x00
            data = bytes(data)
            dataEapol.append(data)
            packetNumber += 1
            continue
        #разбор 4 хендшейка аналогично 2 и 3, но без доставания поля Key Nonce
        if packet.haslayer(EAPOL) and packetNumber == 4:
            data = bytes(packet.getlayer(EAPOL))
            mic = data[81:97]
            mics.append(mic)
            data = list(data)
            for i in range(16):
                data[81 + i] = 0x00
            data = bytes(data)
            dataEapol.append(data)
        if (version == 1):#определяем версию wpa
            isWpa1 = True
        else:
            isWpa1 = False
    return (a2b_hex(sAddr), a2b_hex(dAddr), nonces, mics, dataEapol, isWpa1)

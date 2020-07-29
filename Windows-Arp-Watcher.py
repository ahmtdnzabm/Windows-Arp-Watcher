from scapy.all import *
import os
import re


x = """    #######################################################
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
    #              Windows Arp Watcher v1                 #
    #                 ahmtdnabm                           #
    #                                                     #
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
    #######################################################
    """


def arp_izle(pkt):
    if pkt[ARP].op==2: #Arp Request kontrolü yapılıyor...

        if  ip_mac.get(pkt[ARP].psrc)==None: ##Gelen paket kaydımızda yoksa,yeni kayıt olarak sözlüğümüze ekliyoruz.
             print("\nYeni cihaz kaydedildi {} : {}\n".format(pkt[ARP].psrc,pkt[ARP].hwsrc))
             ip_mac[pkt[ARP].psrc]=pkt[ARP].hwsrc
             [print(ip, mac) for ip, mac in ip_mac.items()]#Yeni arp tablosunu ekrana yazdırtıyoruz.

        elif ip_mac.get(pkt[ARP].psrc) and  ip_mac[pkt[ARP].psrc]!=pkt[ARP].hwsrc: #Gelen İp bilgisi kayıtta var ve karşılığındaki mac farklıysa
          print("\n{}  -  {} İp-Mac Bilgisi {}  -  {} olarak değiştirildi...\n".format(pkt[ARP].psrc,ip_mac[pkt[ARP].psrc],pkt[ARP].psrc,pkt[ARP].hwsrc))
          ip_mac[pkt[ARP].psrc]=pkt[ARP].hwsrc
          [print(ip, mac) for ip, mac in ip_mac.items()] #Yeni arp tablosunu ekrana yazdırtıyoruz.




def main():
    print(x)
    arptablo=os.popen('arp -a').read()#Arp tablosu os modülü ile elde edildi,elde edilen veriler arptablo değişkenine atandı.
    global ip_mac
    ip_mac={}#Sözlük tanımlandı.


    for satir in arptablo.split('\n')[3:]: #İp&Mac bilgilerinin başladığı alandan itibaren döngü başlattık.
        bilgi=re.sub(' +', ' ', satir.strip()+'\n').replace("-",":") #En başdaki boşluğu siler ve birden fazla olan boşlukları tek boşluk haline getirir.
        try:
         ip_mac[(bilgi.split(' ')[0])] = (bilgi.split(' ')[1])#Yukarıda oluşturduğumuz sözlüğe ip-mac adres bilgilerini atar.
        except:
         continue
    [print (ip, mac) for ip,mac in ip_mac.items()] ##Oluşturulan arp tablosunu ekrana yazdırtıyoruz.

    sniff(prn=arp_izle,filter='arp',store=0)

if __name__ == '__main__':
    main()

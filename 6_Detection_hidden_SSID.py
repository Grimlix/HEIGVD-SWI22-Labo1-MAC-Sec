#!/usr/bin/env python3 
# TODO : J'arrive toujours pas a kill le processus avec une interruption..

import argparse
from faker import Faker

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Detection of hidden SSID",
                                 usage="%(prog)s -i wlan0mon -t 300",
                                 description="Detection of hidden SSID",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

parser.add_argument("-t", "--Timeout", required=False,
                    help="The time in secondes how long we will scan for hidden SSID, default is 60", default=60)                 

args = parser.parse_args()

####################################
################## variables ##################

IFACE_NAME = args.Interface
timeout = args.Timeout
hidden_ssid = []

#Classe représentant un AP
class AP:
    def __init__(self, BSSID, SSID):
        self.BSSID = BSSID
        self.SSID = SSID

# Si jamais l'interface est down
#os.system("ifconfig %s up" % IFACE_NAME)
#Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
#p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

####################################
################## fonctions ##################

def PacketHandler(pkt):

    if pkt.haslayer(Dot11Elt):

        # Récupérer le BSSID de l'AP et le SSID (il peut être vide car hidden)
        mac_ap = pkt.addr3
        ssid = pkt.info.decode()
        
        # Si c'est un trame Beacon et qu'il n'a pas de SSID il est caché
        # on va vouloir l'ajouter dans le tableau
        if pkt.haslayer(Dot11Beacon) and not pkt.info:

            # On vérifie que le BSSID ne se trouve pas déjà dans le tableau
            contains = False
            for ap in hidden_ssid:
                if ap.BSSID == mac_ap:
                    contains = True

            # S'il n'y est pas on l'ajoute et on affiche un message
            # il faut maintenant attendre une Probe Request sur cet AP
            if not contains:
                hidden_ssid.append(AP(mac_ap, ssid))
                print("Found a hidden BSSID %s" % mac_ap)

        # Si c'est une Probe Request on veut comparer les BSSID afin de trouvé le SSID
        # correspondantau
        elif pkt.haslayer(Dot11ProbeResp):
            for ap in hidden_ssid:
                if ap.BSSID == mac_ap:
                    ap.SSID = ssid
                    print("BSSID : %s \t SSID : %s" % (ap.BSSID, ap.SSID))
                    break
            

####################################
################## main ##################

sniff(iface=IFACE_NAME, prn=PacketHandler, timeout=int(timeout))
 










#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Nicolas Hungerbühler & Lucas Gianinetti
# Created Date: 31.03.22
# ---------------------------------------------------------------------------
# Ce programme liste les APs et stations à proximité. Il indique quelle
# station est connectée à quel AP.
# Il prend en paramètre une interface réseau (/!\ Doit être en mode
# monitor channel hopping /!\), et un SSID
# ---------------------------------------------------------------------------
# https://stackoverflow.com/questions/52981542/python-scapy-distinguish-between-acesspoint-to-station

import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy STA Detection and link with AP",
                                 usage="%(prog)s -i wlan0mon",
                                 description="Scapy STA Detection and link with AP",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

args = parser.parse_args()

################## variables ##################

IFACE_NAME = args.Interface
BROADCAST = "ff:ff:ff:ff:ff:ff"
sta_ap_list = []


################## fonctions ##################

def PacketHandler(pkt):
    # On veut les trames Data (donc linkées entre deux entités)
    # et non broadcast (on veut que STA <-> AP)
    if pkt.haslayer(Dot11) and pkt.type == 2:

        # On récupère les differentes adresses
        dest_mac = pkt.addr1
        src_mac = pkt.addr2
        ap_mac = pkt.addr3

        # On vérifie que ce soit bien une trame d'un AP et non broadcast
        if dest_mac != BROADCAST and src_mac != BROADCAST: 

            #Il faut maintenant distinguer une STA d'une AP
            #Si dest_mac != ap_mac ça veut dire que la STA est l'adresse de destination
            if dest_mac != ap_mac:
                sta_ap = (dest_mac, ap_mac)
            else:
                sta_ap = (src_mac, ap_mac)

            # Verification si doublon et affichage
            if sta_ap not in sta_ap_list:
                sta_ap_list.append(sta_ap)
                print(sta_ap[0] + "\t" + sta_ap[1])

################## main ##################
            
print("STA\t\t\tAP")
sniff(iface=IFACE_NAME, prn=PacketHandler)
 










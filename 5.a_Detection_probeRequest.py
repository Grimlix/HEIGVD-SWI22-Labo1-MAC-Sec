#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Nicolas Hungerbühler & Lucas Gianinetti
# Created Date: 31.03.22
# ---------------------------------------------------------------------------
# Ce programme liste toutes les stations cherchant activement le SSID passé
# en paramètre.
# Il prend en paramètre une interface réseau (/!\ Doit être en mode
# monitor channel hopping /!\), et un SSID
# ---------------------------------------------------------------------------

import argparse
from faker import Faker

from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11ProbeReq

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy Detection of Probe Request",
                                 usage="%(prog)s -i wlan0mon -ssid McDo",
                                 description="Scapy Detection of Probe Request",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

parser.add_argument("-ssid", "--SSIDname", required=True,
                    help="The SSID we want to is receiving Probe Request") 

args = parser.parse_args()

################## variables ##################

IFACE_NAME = args.Interface
SSID_chosen = args.SSIDname

sta_list = []


################## fonctions ##################

def PacketHandler(pkt):
    # On récupère les Probe request 
    if pkt.haslayer(Dot11ProbeReq):

        # Vérifier que les infos sont disponibles
        if pkt.haslayer(Dot11Elt):

            # On va garder la liaison STA -> AP
            sta = pkt.addr2
            # On récupère le SSID du packet 
            ssid = pkt.info.decode('utf-8')

            # Verification des doublons et que le SSID et celui qu'on veut
            if ssid == SSID_chosen and sta not in sta_list:
                sta_list.append(sta)
                print("STA (%s) is looking for the given SSID (%s)" % (sta, ssid))

################## main ##################

sniff(iface=IFACE_NAME, prn=PacketHandler)
 










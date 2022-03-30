# https://www.thepythoncode.com/article/create-fake-access-points-scapy
# https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

import argparse

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq

# Passing arguments
parser = argparse.ArgumentParser(prog="Scapy fake evil tween attack",
                                 usage="%(prog)s -i wlan0mon",
                                 description="Scapy bases fake evil tween attack",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="the interface we want to sniff to be on, needs to be set to monitor mode with channel hopping")

args = parser.parse_args()

IFACE_NAME = args.Interface

# Si jamais l'interface est down
os.system("ifconfig %s up" % IFACE_NAME)
#Launch airodump-ng en background / screen permet de ne pas afficher sur la console le process passé en argument
p = subprocess.Popen(['screen','-d','-m','airodump-ng',IFACE_NAME])

ap_bssid_list = []
ap_list = []

def PacketHandler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        mac = str(pkt.addr2)
        if pkt.haslayer(Dot11Elt):
            if pkt.addr2 not in ap_bssid_list:
                ap_bssid_list.append(pkt.addr2)

                ADDR2 = pkt.addr2
                BSSID = pkt.addr3
                SSID = pkt.info.decode("utf-8")
                #channel = pkt.channel
                print("MAC: %s \t ADDR2: %s \t SSID: %s" % (BSSID, ADDR2, SSID))


sniff(iface=IFACE_NAME, prn=PacketHandler)

p.kill()









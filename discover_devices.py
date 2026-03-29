from scapy.all import ARP, Ether, srp
from netaddr import EUI

def scan(network, interface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
    result = srp(packet, iface=interface, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        mac = received.hwsrc
        try:
            vendor = EUI(mac).oui.registration().org
        except:
            vendor = "Unknown"
        print(f"IP: {received.psrc} | MAC: {mac} | Vendor: {vendor}")
        devices.append({"ip": received.psrc, "mac": mac, "vendor": vendor})
    return devices

print("=== IoT Network ===")
scan("192.168.20.0/24", "docker-iot")

print("\n=== Trusted Network ===")
scan("192.168.10.0/24", "ens37")

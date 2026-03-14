from scapy.all import sniff
from detector import detect_port_scan

def packet_handler(packet):
    detect_port_scan(packet)

def start_nids():
    print("=======================================")
    print(" Network Intrusion Detection System ")
    print("=======================================")
    print("Monitoring network traffic...\n")

    # sniff packets continuously
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    start_nids()

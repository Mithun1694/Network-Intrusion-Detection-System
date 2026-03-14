from scapy.layers.inet import IP, TCP
import logging

# Dictionary to store ports accessed by each IP
ip_ports = {}

# Configure logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Threshold for port scanning
PORT_SCAN_THRESHOLD = 10

def detect_port_scan(packet):

    # Check if packet contains IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Create entry for new IP
        if src_ip not in ip_ports:
            ip_ports[src_ip] = set()

        # Store accessed port
        ip_ports[src_ip].add(dst_port)

        # Detect port scan
        if len(ip_ports[src_ip]) > PORT_SCAN_THRESHOLD:

            alert_message = f"[ALERT] Possible Port Scan Detected from {src_ip}"

            print(alert_message)

            logging.info(alert_message)

            # reset tracking
            ip_ports[src_ip].clear()

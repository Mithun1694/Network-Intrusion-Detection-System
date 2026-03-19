from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import threading
import datetime
import os

# ======================================
# CONFIGURATION
# ======================================

INTERFACE = "eth0"
LOG_FILE = "/home/kali/network-intrusion-detection-system/alerts.log"

PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 12
TIME_WINDOW = 10

ALERT_COOLDOWN = 10

ENABLE_BLOCKING = False   # ⚠ Set True to enable firewall blocking

# ======================================
# DATA STRUCTURES
# ======================================

port_tracker = defaultdict(set)
syn_tracker = defaultdict(list)
login_tracker = defaultdict(list)

suspicious_ips = set()

stats = {
    "port_scan": 0,
    "syn_flood": 0,
    "brute_force": 0
}

last_alert_time = {}

# ======================================
# ALERT FUNCTION
# ======================================

def alert(attack_type, src_ip, dst_port="N/A"):

    now = time.time()
    key = f"{attack_type}_{src_ip}"

    if key in last_alert_time and now - last_alert_time[key] < ALERT_COOLDOWN:
        return False

    last_alert_time[key] = now

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = f"[{timestamp}] {attack_type} | Source: {src_ip} | Port: {dst_port}"

    print(message)

    try:
        with open(LOG_FILE, "a") as f:
            f.write(message + "\n")
    except Exception as e:
        print("Log error:", e)

    return True

# ======================================
# IP BLOCKING (OPTIONAL)
# ======================================

def block_ip(ip):

    if not ENABLE_BLOCKING:
        return

    print(f"[BLOCK] Blocking IP: {ip}")

    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

# ======================================
# DETECTION FUNCTIONS
# ======================================

def detect_port_scan(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src = packet[IP].src
        port = packet[TCP].dport

        port_tracker[src].add(port)

        if len(port_tracker[src]) > PORT_SCAN_THRESHOLD:

            if alert("PORT_SCAN", src, port):

                stats["port_scan"] += 1
                suspicious_ips.add(src)
                block_ip(src)

            port_tracker[src].clear()

# --------------------------------------

def detect_syn_flood(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src = packet[IP].src

        if packet[TCP].flags == "S":

            now = time.time()

            syn_tracker[src].append(now)

            syn_tracker[src] = [
                t for t in syn_tracker[src]
                if now - t < TIME_WINDOW
            ]

            if len(syn_tracker[src]) > SYN_FLOOD_THRESHOLD:

                if alert("SYN_FLOOD", src):

                    stats["syn_flood"] += 1
                    suspicious_ips.add(src)
                    block_ip(src)

                syn_tracker[src].clear()

# --------------------------------------

def detect_bruteforce(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src = packet[IP].src
        port = packet[TCP].dport

        if port == 22:

            now = time.time()

            login_tracker[src].append(now)

            login_tracker[src] = [
                t for t in login_tracker[src]
                if now - t < TIME_WINDOW
            ]

            if len(login_tracker[src]) > BRUTE_FORCE_THRESHOLD:

                if alert("SSH_BRUTE_FORCE", src, port):

                    stats["brute_force"] += 1
                    suspicious_ips.add(src)
                    block_ip(src)

                login_tracker[src].clear()

# --------------------------------------

def detect_suspicious_ip(packet):

    if packet.haslayer(IP):

        src = packet[IP].src

        if src in suspicious_ips:

            alert("SUSPICIOUS_IP_ACTIVITY", src)

# ======================================
# PACKET HANDLER
# ======================================

def packet_handler(packet):

    try:

        detect_port_scan(packet)
        detect_syn_flood(packet)
        detect_bruteforce(packet)
        detect_suspicious_ip(packet)

    except Exception as e:

        print("Packet error:", e)

# ======================================
# STATISTICS DISPLAY
# ======================================

def show_stats():

    while True:

        time.sleep(20)

        print("\n========= NIDS STATS =========")

        print("Port Scans:", stats["port_scan"])
        print("SYN Floods:", stats["syn_flood"])
        print("Brute Force:", stats["brute_force"])
        print("Suspicious IPs:", list(suspicious_ips))

        print("==============================\n")

# ======================================
# START NIDS
# ======================================

def start_nids():

    print("\n================================")
    print(" Network Intrusion Detection System")
    print("================================\n")

    print("Monitoring network traffic...\n")

    sniff(
        iface=INTERFACE,
        prn=packet_handler,
        store=False
    )

# ======================================
# MAIN
# ======================================

if __name__ == "__main__":

    stats_thread = threading.Thread(target=show_stats)
    stats_thread.daemon = True
    stats_thread.start()

    start_nids()

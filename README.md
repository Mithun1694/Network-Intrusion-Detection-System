# 🔐 Network Intrusion Detection System (NIDS) with SOC Dashboard

A real-time Network Intrusion Detection System built using Python and Scapy, integrated with a SOC-style dashboard to monitor, detect, and visualize network threats.

---

## 🚀 Features

* Real-time packet monitoring
* Detection of:

  * Port Scanning
  * SYN Flood Attacks
  * SSH Brute Force Attempts
* Live dashboard with:

  * Attack counters
  * Attack graph & timeline
  * Top attackers panel
* IP geolocation with attack map
* Clean logging with timestamps

---

## 🛠️ Tech Stack

* Python
* Scapy
* Flask
* Chart.js
* Leaflet.js

---

## 📂 Project Structure

```
network-intrusion-detection-system/
├── nids.py
├── dashboard.py
├── alerts.log
├── requirements.txt
└── templates/
    └── index.html
```

---

## ⚙️ Setup

```bash
git clone https://github.com/your-username/network-intrusion-detection-system.git
cd network-intrusion-detection-system
pip install -r requirements.txt
```

---

## ▶️ Run

Start NIDS:

```bash
sudo python3 nids.py
```

Start dashboard:

```bash
python3 dashboard.py
```

Open:

```
http://localhost:5000
```

---

## 🧪 Testing

Run a safe port scan:

```bash
nmap -sS -T4 -p 1-200 scanme.nmap.org
```

---

## 📊 Sample Output

```
[2026-03-19 16:38:13] PORT_SCAN | Source: 208.95.112.1
```

---

## 🌍 Dashboard Includes

* Real-time attack graph
* Timeline visualization
* Top attackers (by frequency)
* Geolocation map of attackers

---

## 📸 Screenshots

*Add your screenshots here*

```
screenshots/dashboard.png
screenshots/map.png
screenshots/terminal.png
```

---

## ⚠️ Notes

* Private IPs (127.0.0.1, 10.x.x.x) are not geolocated
* Use only authorized targets for testing
* False positives are reduced using filtering logic

---

## 👨‍💻 Author

Mithun 
Cybersecurity Enthusiast

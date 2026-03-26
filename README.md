# 🔐 Network Intrusion Detection System (NIDS) with SOC Dashboard(only for linux system)

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
git clone https://github.com/Mithun1694/Network-Intrusion-Detection-System.git
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

<img width="1885" height="909" alt="image" src="https://github.com/user-attachments/assets/b94400c2-7006-487d-86ec-27db8b4e3157" />

<img width="1886" height="906" alt="image" src="https://github.com/user-attachments/assets/c4e057fc-0d7c-4ec1-9a4d-3ab8c92f9ce4" />

<img width="1638" height="786" alt="image" src="https://github.com/user-attachments/assets/29a4edbe-5ae0-4b3a-b0e8-0c58e74e7c5e" />

[Sample log](alerts.log)


---

## 🌍 Dashboard Includes

* Real-time attack graph
* Timeline visualization
* Top attackers (by frequency)
* Geolocation map of attackers



---

## ⚠️ Notes

* Private IPs (127.0.0.1, 10.x.x.x) are not geolocated
* Use only authorized targets for testing
* False positives are reduced using filtering logic

---

## 👨‍💻 Author

Mithun 
Cybersecurity Enthusiast

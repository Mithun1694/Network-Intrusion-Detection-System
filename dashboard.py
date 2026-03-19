from flask import Flask, render_template, jsonify
import requests

app = Flask(__name__)

LOG_FILE = "alerts.log"

# ===============================
# PARSE LOGS
# ===============================

def parse_logs():

    counts = {
        "PORT_SCAN": 0,
        "SYN_FLOOD": 0,
        "SSH_BRUTE_FORCE": 0,
        "SUSPICIOUS_IP_ACTIVITY": 0
    }

    alerts = []
    suspicious_ips = set()
    attacker_counts = {}

    try:
        with open(LOG_FILE) as f:

            for line in f:

                line = line.strip()
                alerts.append(line)

                if "Source:" in line:
                    ip = line.split("Source: ")[1].split(" |")[0]

                else:
                    continue

                # Count attacks
                if "PORT_SCAN" in line:
                    counts["PORT_SCAN"] += 1

                elif "SYN_FLOOD" in line:
                    counts["SYN_FLOOD"] += 1

                elif "SSH_BRUTE_FORCE" in line:
                    counts["SSH_BRUTE_FORCE"] += 1

                # Track suspicious IPs
                if "PORT_SCAN" in line or "SYN_FLOOD" in line or "SSH_BRUTE_FORCE" in line:
                    suspicious_ips.add(ip)

                    # 🔥 COUNT PER IP
                    attacker_counts[ip] = attacker_counts.get(ip, 0) + 1

    except:
        pass

    counts["SUSPICIOUS_IP_ACTIVITY"] = len(suspicious_ips)

    # 🔥 SORT TOP ATTACKERS
    top_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)

    return counts, alerts[-20:], list(suspicious_ips), top_attackers
# ===============================
# GEO LOCATION
# ===============================

def get_location(ip):

    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127."):
        return None

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()

        if res.get("status") != "success":
            return None

        return {
            "ip": ip,
            "lat": res.get("lat"),
            "lon": res.get("lon"),
            "country": res.get("country")
        }

    except:
        return None

# ===============================
# ROUTES
# ===============================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():

    counts, alerts, _, top_attackers = parse_logs()

    return jsonify({
        "counts": counts,
        "alerts": alerts,
        "top_attackers": top_attackers[:5]   # top 5
    })

@app.route("/map")
def map_data():

    _, _, ips, _ = parse_logs()   # ✅ FIXED

    locations = []

    for ip in ips:

        loc = get_location(ip)

        if loc and loc.get("lat") and loc.get("lon"):
            locations.append(loc)

    return jsonify(locations)
# ===============================
# MAIN
# ===============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

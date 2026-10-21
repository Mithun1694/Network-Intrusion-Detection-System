from flask import Flask, render_template, jsonify
from collections import Counter
from datetime import datetime
from pathlib import Path
import os
import re
import requests

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = Path(os.environ.get("NIDS_LOG_FILE", BASE_DIR / "alerts.log"))

ATTACK_TYPES = {
    "PORT_SCAN": "Port Scan",
    "SYN_FLOOD": "SYN Flood",
    "SSH_BRUTE_FORCE": "Brute Force",
    "SUSPICIOUS_IP_ACTIVITY": "Suspicious IP Activity",
}

LINE_RE = re.compile(
    r"^\[(?P<timestamp>.*?)\]\s+(?P<type>[A-Z_]+)\s+\|\s+Source:\s+(?P<ip>[0-9a-fA-F:.]+)\s+\|\s+Port:\s+(?P<port>[^|]+)"
)

def parse_logs():
    """Read the current log file and return normalized alert records."""
    records = []
    if not LOG_FILE.exists():
        return records

    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                match = LINE_RE.match(line)
                if match:
                    item = match.groupdict()
                    item["port"] = item["port"].strip()
                    records.append(item)
                elif line:
                    records.append({
                        "timestamp": "",
                        "type": "UNKNOWN",
                        "ip": "Unknown",
                        "port": "N/A",
                        "raw": line,
                    })
    except OSError:
        app.logger.exception("Could not read NIDS log file")
    return records

def is_private_ip(ip):
    return ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.",
                          "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                          "fe80:", "fc", "fd"))

def get_location(ip):
    # Private/local IP addresses cannot be mapped to a public geographic location.
    if is_private_ip(ip) or ip in ("Unknown", ""):
        return None
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,lat,lon,query"},
            timeout=2.5,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("status") != "success":
            return None
        return {
            "ip": ip,
            "lat": result.get("lat"),
            "lon": result.get("lon"),
            "country": result.get("country") or "Unknown",
        }
    except (requests.RequestException, ValueError):
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    records = parse_logs()
    counts = Counter(record["type"] for record in records)
    attack_records = [r for r in records if r["type"] in ATTACK_TYPES]
    attacker_counts = Counter(r["ip"] for r in attack_records if r["ip"] != "Unknown")
    suspicious_ips = sorted({
        r["ip"] for r in records
        if r["type"] in ("PORT_SCAN", "SYN_FLOOD", "SSH_BRUTE_FORCE", "SUSPICIOUS_IP_ACTIVITY")
        and r["ip"] != "Unknown"
    })

    timeline = []
    buckets = Counter()
    for record in attack_records[-300:]:
        stamp = record.get("timestamp", "")
        if stamp:
            try:
                dt = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
                key = dt.strftime("%H:%M")
                buckets[key] += 1
            except ValueError:
                continue
    timeline = [{"time": k, "count": v} for k, v in sorted(buckets.items())][-20:]

    country_counts = Counter()
    # Country totals are filled from cached map lookups on the client; the
    # endpoint also includes records so the UI can show data without geolocation.
    recent_alerts = []
    for record in reversed(records[-100:]):
        recent_alerts.append({
            "timestamp": record.get("timestamp", ""),
            "type": record.get("type", "UNKNOWN"),
            "label": ATTACK_TYPES.get(record.get("type"), record.get("type", "UNKNOWN").replace("_", " ").title()),
            "ip": record.get("ip", "Unknown"),
            "port": record.get("port", "N/A"),
            "severity": (
                "High" if record.get("type") in ("SYN_FLOOD", "SSH_BRUTE_FORCE", "PORT_SCAN")
                else "Medium" if record.get("type") == "SUSPICIOUS_IP_ACTIVITY"
                else "Low"
            ),
        })

    return jsonify({
        "counts": {
            "PORT_SCAN": counts["PORT_SCAN"],
            "SYN_FLOOD": counts["SYN_FLOOD"],
            "SSH_BRUTE_FORCE": counts["SSH_BRUTE_FORCE"],
            "SUSPICIOUS_IP_ACTIVITY": len(suspicious_ips),
            "TOTAL_ALERTS": len(records),
        },
        "top_attackers": [
            {"ip": ip, "count": count} for ip, count in attacker_counts.most_common(8)
        ],
        "timeline": timeline,
        "alerts": recent_alerts[:25],
        "ips": suspicious_ips,
        "log_file": LOG_FILE.name,
    })

@app.route("/map")
def map_data():
    records = parse_logs()
    ips = list(dict.fromkeys(
        r["ip"] for r in records
        if r["type"] in ("PORT_SCAN", "SYN_FLOOD", "SSH_BRUTE_FORCE", "SUSPICIOUS_IP_ACTIVITY")
    ))[-30:]
    locations = []
    for ip in ips:
        location = get_location(ip)
        if location:
            locations.append(location)
    return jsonify(locations)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "log_file_exists": LOG_FILE.exists()})

if __name__ == "__main__":
    app.run(host=os.environ.get("NIDS_HOST", "127.0.0.1"),
            port=int(os.environ.get("NIDS_PORT", "5000")),
            debug=False)

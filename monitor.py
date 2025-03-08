import requests
import os
import sqlite3
import time
import threading
import folium
from folium.plugins import HeatMap
from scapy.all import sniff, IP, ICMP, TCP, ARP, UDP
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ABUSEIPDB_API_KEY

conn = sqlite3.connect("attacks.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        attacker_ip TEXT,
        attack_type TEXT,
        country TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL
    )
""")
conn.commit()

def get_geo_location(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url).json()
        if response["status"] == "fail":
            return "Unknown", "Unknown", 0, 0
        return response["country"], response["city"], response["lat"], response["lon"]
    except:
        return "Unknown", "Unknown", 0, 0

def generate_attack_heatmap():
    cursor.execute("SELECT latitude, longitude FROM attack_log WHERE latitude != 0 AND longitude != 0")
    locations = cursor.fetchall()
    heatmap = folium.Map(location=[20, 0], zoom_start=2)
    HeatMap(locations).add_to(heatmap)
    heatmap_file = "heatmap.html"
    heatmap.save(heatmap_file)
    return heatmap_file

last_heatmap_time = 0

def send_heatmap():
    global last_heatmap_time
    current_time = time.time()
    if current_time - last_heatmap_time < 600:
        return
    last_heatmap_time = current_time  
    heatmap_file = generate_attack_heatmap()
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    files = {"document": open(heatmap_file, "rb")}
    data = {"chat_id": TELEGRAM_CHAT_ID, "caption": "Live Attack Heatmap"}
    requests.post(url, files=files, data=data)

def block_ip(ip):
    os.system(f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null || sudo iptables -A INPUT -s {ip} -j DROP")
    send_telegram_message(f"Blocked: {ip}")

def unblock_ip(ip):
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null || echo 'IP {ip} was not blocked'")
    send_telegram_message(f"Unblocked: {ip}")

reported_ips = {}

def report_to_abuseipdb(ip, attack_type):
    current_time = time.time()
    if ip in reported_ips and (current_time - reported_ips[ip] < 900):
        return  
    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    data = {"ip": ip, "categories": "14, 18", "comment": f"Detected {attack_type} attack."}
    requests.post(url, headers=headers, data=data)
    reported_ips[ip] = current_time  

def send_telegram_message(text, buttons=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}
    if buttons:
        keyboard = {"inline_keyboard": buttons}
        data["reply_markup"] = keyboard
    requests.post(url, json=data)

attack_log = {}

def detect_attack(pkt):
    if pkt.haslayer(IP):
        attacker_ip = pkt[IP].src
        attack_type = None
        if attacker_ip.startswith(("192.", "10.", "127.")):
            return  
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            attack_type = "Ping Flood"
        elif pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            attack_type = "SYN Scan"
        elif pkt.haslayer(UDP) and len(pkt[UDP].payload) > 100:
            attack_type = "UDP Flood"
        elif pkt.haslayer(ARP) and pkt[ARP].op == 2:
            attack_type = "ARP Spoofing"
        else:
            return
        country, city, lat, lon = get_geo_location(attacker_ip)
        current_time = time.time()
        if attacker_ip in attack_log and (current_time - attack_log[attacker_ip] < 900):
            return  
        attack_log[attacker_ip] = current_time  
        buttons = [
            [
                {"text": "Block", "callback_data": f"block:{attacker_ip}"},
                {"text": "Unblock", "callback_data": f"unblock:{attacker_ip}"},
                {"text": "Report", "callback_data": f"report:{attacker_ip}"}
            ]
        ]
        send_telegram_message(
            f"{attack_type} Detected!\nAttacker IP: {attacker_ip}\nLocation: {city}, {country}",
            buttons
        )
        cursor.execute("INSERT INTO attack_log (timestamp, attacker_ip, attack_type, country, city, latitude, longitude) VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)", 
                       (attacker_ip, attack_type, country, city, lat, lon))
        conn.commit()
        block_ip(attacker_ip)
        report_to_abuseipdb(attacker_ip, attack_type)

def handle_telegram_commands():
    while True:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
        response = requests.get(url).json()
        if "result" in response:
            for update in response["result"]:
                if "message" in update and "text" in update["message"]:
                    command = update["message"]["text"].strip().lower()
                    if command == "/heatmap":
                        send_heatmap()
                    elif command.startswith("/block "):
                        ip_to_block = command.split(" ")[1]
                        block_ip(ip_to_block)
                    elif command.startswith("/unblock "):
                        ip_to_unblock = command.split(" ")[1]
                        unblock_ip(ip_to_unblock)
        time.sleep(5)

threading.Thread(target=handle_telegram_commands, daemon=True).start()

sniff(filter="icmp or tcp or udp or arp", prn=detect_attack, store=0)


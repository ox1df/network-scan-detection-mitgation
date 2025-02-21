# 🦅 PingHawk - Real-Time Network Attack Monitor

PingHawk is a **real-time network attack detection & response system** that sniffs traffic, detects malicious activities, logs them, and takes automated actions like blocking attackers, reporting them to AbuseIPDB, and sending alerts via Telegram.

## 🚀 Features

✅ **Detects Attacks:**
- 🔥 Ping Flood (ICMP)
- 🕵️ SYN Scan (TCP)
- ⚡ UDP Flood (Large UDP Payloads)
- 🎭 ARP Spoofing (ARP Responses)

✅ **Automated Responses:**
- 🚫 Blocks malicious IPs using `iptables`
- 📡 Reports attackers to **AbuseIPDB**
- 🌍 Logs attack details with **Geo-IP location**
- 📊 Generates a **heatmap of attack sources**
- 📨 Sends real-time alerts & interactive buttons via **Telegram**

---

## 🔧 Installation

1️⃣ **Clone the Repository**
```bash
 git clone https://github.com/yourusername/PingHawk.git
 cd PingHawk
```

2️⃣ **Install Dependencies**
```bash
pip install requests scapy folium
```

3️⃣ **Set Up Configuration**
Create a `config.py` file and add the following details:
```python
TELEGRAM_BOT_TOKEN = "your-telegram-bot-token"
TELEGRAM_CHAT_ID = "your-chat-id"
ABUSEIPDB_API_KEY = "your-abuseipdb-api-key"
```

4️⃣ **Run PingHawk**
```bash
sudo python pinghawk.py
```
*(Requires sudo for `iptables` operations)*

---

## 📜 How It Works

- **Sniffs network traffic** using Scapy
- **Detects malicious activity** and logs attacker details
- **Sends alerts to Telegram** with inline buttons:
  - 🚫 Block Attacker
  - ✅ Unblock IP
  - 📡 Report to AbuseIPDB
- **Blocks attacker IPs** using `iptables`
- **Generates a live attack heatmap** on request

---

## 📲 Telegram Commands
- `/heatmap` → Generates & sends attack heatmap
- `/block <ip>` → Blocks the specified IP
- `/unblock <ip>` → Unblocks the specified IP

---

## 🌟 Future Enhancements
- [ ] Web-based dashboard for live attack monitoring
- [ ] Machine Learning model for anomaly detection
- [ ] Integration with **Suricata** for deeper threat analysis

---

## 💀 Author
🚀 Developed by **Your Name**

🔗 GitHub: [ox1df](https://github.com/ox1df)  
💬 Telegram: [Shadowstrike_ru](https://t.me/Shadowstrike_ru)

---



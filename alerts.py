import sqlite3
import requests
import datetime
import os

DB_NAME = "threat_logs.db"

class ThreatNotifier:
    def __init__(self, discord_webhook_url=None, telegram_token=None, telegram_chat_id=None):
        self.discord_url = discord_webhook_url
        self.tg_token = telegram_token
        self.tg_chat_id = telegram_chat_id
        self._init_db()

    def _init_db(self):
        """Initialize the local SQLite database for persistent threat logging."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                details TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_threat(self, threat_type, severity, details):
        """Save threat event to local database and trigger alerts."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1. Save to Database
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO threats (timestamp, threat_type, severity, details) VALUES (?, ?, ?, ?)",
                (timestamp, threat_type, severity, details)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Database Error: {e}")

        # 2. Format Message
        alert_message = (
            f"🚨 **SECURITY ALERT: {threat_type}** 🚨\n"
            f"• **Severity:** {severity}\n"
            f"• **Time:** {timestamp}\n"
            f"• **Details:** {details}"
        )

        print(f"[{severity}] {threat_type}: {details}")

        # 3. Send Notifications
        if self.discord_url:
            self._send_discord(alert_message)
        if self.tg_token and self.tg_chat_id:
            self._send_telegram(alert_message)

    def _send_discord(self, message):
        """Sends rich-text alerts to a Discord channel via webhook."""
        try:
            payload = {"content": message}
            response = requests.post(self.discord_url, json=payload, timeout=5)
            if response.status_code != 204:
                print(f"[-] Discord webhook failed with status code {response.status_code}")
        except Exception as e:
            print(f"[-] Failed to dispatch Discord alert: {e}")

    def _send_telegram(self, message):
        """Sends alerts via Telegram Bot API."""
        try:
            url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            payload = {
                "chat_id": self.tg_chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code != 200:
                print(f"[-] Telegram alert failed: {response.text}")
        except Exception as e:
            print(f"[-] Failed to dispatch Telegram alert: {e}")

# Example integration test
if __name__ == "__main__":
    # Initialize without credentials to test local DB logging first
    notifier = ThreatNotifier()
    notifier.log_threat(
        threat_type="Unauthorized Port Scan",
        severity="HIGH",
        details="Detected rapid sequential SYN packets from IP 192.168.1.50"
    )

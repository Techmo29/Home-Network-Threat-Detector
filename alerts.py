import sqlite3
import requests
import datetime
import os
import json
import threading
import time

DB_NAME = "threat_logs.db"

class ThreatNotifier:
    def __init__(self, config_path="config.json", discord_webhook_url=None, telegram_token=None, telegram_chat_id=None):
        # 1. Load from config.json if explicit arguments aren't provided
        self.discord_url = discord_webhook_url
        self.tg_token = telegram_token
        self.tg_chat_id = telegram_chat_id
        
        if os.path.exists(config_path) and (not self.discord_url or not self.tg_token):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                    self.discord_url = self.discord_url or config.get("discord_webhook_url")
                    self.tg_token = self.tg_token or config.get("telegram_token")
                    self.tg_chat_id = self.tg_chat_id or config.get("telegram_chat_id")
            except Exception as e:
                print(f"[-] Error reading config file: {e}")

        # 2. Throttling cache to prevent notification spam (Key: threat_key, Value: timestamp)
        self._recent_alerts = {}
        self._throttle_lock = threading.Lock()
        self.throttle_window = 60  # seconds

        self._init_db()

    def _init_db(self):
        """Initialize the local SQLite database with WAL mode for concurrency."""
        try:
            with sqlite3.connect(DB_NAME) as conn:
                # Enable Write-Ahead Logging to support concurrent multi-script writes
                conn.execute("PRAGMA journal_mode=WAL;")
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
        except Exception as e:
            print(f"[-] Database Initialization Error: {e}")

    def log_threat(self, threat_type, severity, details):
        """Save threat event to local database and trigger throttled async alerts."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1. Save to Database using safe context managers
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO threats (timestamp, threat_type, severity, details) VALUES (?, ?, ?, ?)",
                    (timestamp, threat_type, severity, details)
                )
                conn.commit()
        except Exception as e:
            print(f"[-] Database Write Error: {e}")

        # Print locally immediately
        print(f"[{severity}] {threat_type}: {details}")

        # 2. Check Throttling / Rate-Limiting
        alert_key = f"{threat_type}:{details}"
        now = time.time()
        with self._throttle_lock:
            last_sent = self._recent_alerts.get(alert_key, 0)
            if now - last_sent < self.throttle_window:
                return  # Suppress duplicate alert within the time window
            self._recent_alerts[alert_key] = now

        # 3. Format Message
        alert_message = (
            f"🚨 **SECURITY ALERT: {threat_type}** 🚨\n"
            f"• **Severity:** {severity}\n"
            f"• **Time:** {timestamp}\n"
            f"• **Details:** {details}"
        )

        # 4. Dispatch Notifications asynchronously via background threads
        if self.discord_url:
            threading.Thread(target=self._send_discord, args=(alert_message,), daemon=True).start()
        if self.tg_token and self.tg_chat_id:
            threading.Thread(target=self._send_telegram, args=(alert_message,), daemon=True).start()

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
    notifier = ThreatNotifier()
    notifier.log_threat(
        threat_type="Unauthorized Port Scan",
        severity="HIGH",
        details="Detected rapid sequential SYN packets from IP 192.168.1.50"
    )

import time
import threading
import requests
from datetime import datetime
from scapy.all import sniff, IP, DNS, DNSQR

# Public, free, no-API-key-required threat feeds from Abuse.ch
IP_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
DOMAIN_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"

class ThreatIntelDetector:
    def __init__(self, alert_callback=None):
        self.malicious_ips = set()
        self.malicious_domains = set()
        # Optional hook to connect your existing alerts.py or GUI log
        self.alert_callback = alert_callback or self.default_alert
        self.alerted_cache = {}  # Prevent alert spam for repeated packets
        self.cooldown_seconds = 60

    def update_feeds(self):
        """Fetches fresh IOCs (Indicators of Compromise) into O(1) lookup sets."""
        print(f"[{self._now()}] Updating threat intelligence feeds...")
        
        # 1. Load Malicious C2 IPs (Feodo Tracker)
        try:
            resp = requests.get(IP_FEED_URL, timeout=10)
            if resp.status_code == 200:
                ips = {
                    line.strip()
                    for line in resp.text.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                self.malicious_ips = ips
                print(f"  -> Loaded {len(self.malicious_ips)} malicious C2 IPs.")
        except Exception as e:
            print(f"  [!] Failed to fetch IP feed: {e}")

        # 2. Load Malicious Domains (URLhaus)
        try:
            resp = requests.get(DOMAIN_FEED_URL, timeout=10)
            if resp.status_code == 200:
                domains = set()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Extract domain from URL (e.g., http://evil.com/payload -> evil.com)
                        domain = line.split("//")[-1].split("/")[0].split(":")[0].lower()
                        domains.add(domain)
                self.malicious_domains = domains
                print(f"  -> Loaded {len(self.malicious_domains)} malicious domains.")
        except Exception as e:
            print(f"  [!] Failed to fetch domain feed: {e}")

    def inspect_packet(self, packet):
        """Callback executed by Scapy for every captured packet."""
        # Check IP Layer (Source & Destination)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if src_ip in self.malicious_ips:
                self._trigger_alert("MALICIOUS_IP_INBOUND", src_ip, f"{src_ip} -> {dst_ip}")
            elif dst_ip in self.malicious_ips:
                self._trigger_alert("MALICIOUS_IP_OUTBOUND", dst_ip, f"{src_ip} -> {dst_ip}")

        # Check DNS Layer (Queried Domains)
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # qr == 0 means DNS Query
            if packet.haslayer(DNSQR):
                queried_domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
                if queried_domain in self.malicious_domains:
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    self._trigger_alert("MALICIOUS_DNS_QUERY", queried_domain, f"Device {src_ip} queried {queried_domain}")

    def _trigger_alert(self, threat_type, indicator, details):
        """Throttles duplicate alerts and dispatches to callback."""
        now = time.time()
        last_seen = self.alerted_cache.get(indicator, 0)
        
        if now - last_seen > self.cooldown_seconds:
            self.alerted_cache[indicator] = now
            self.alert_callback(threat_type, indicator, details)

    def default_alert(self, threat_type, indicator, details):
        print(f"\n[ALERT - {self._now()}] {threat_type} | Indicator: {indicator} | {details}")

    @staticmethod
    def _now():
        return datetime.now().strftime("%H:%M:%S")


def start_sniffer(interface=None):
    detector = ThreatIntelDetector()
    detector.update_feeds()

    # Optional: Refresh feeds every 6 hours in a background thread
    def periodic_refresh():
        while True:
            time.sleep(6 * 3600)
            detector.update_feeds()

    threading.Thread(target=periodic_refresh, daemon=True).start()

    print(f"\n[*] Sniffing live packets on {interface or 'default interface'}... (Press Ctrl+C to stop)")
    # store=False is critical so Scapy doesn't fill up RAM over time
    sniff(iface=interface, prn=detector.inspect_packet, store=False)


if __name__ == "__main__":
    # Requires root/sudo on macOS/Linux, or Administrator + Npcap on Windows
    start_sniffer()

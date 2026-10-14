from datetime import datetime
import json
import os
from scapy.all import DNS, DNSQR, IP, UDP, sniff

# Optional local blocklist for suspicious/malicious domains
SUSPICIOUS_DOMAINS = [
    "malicious-example.com",
    "tracker-badguy.net",
    "phishing-site.org",
]

LOG_FILE = "dns_alerts.json"


def log_suspicious_dns(ip_src, domain):
  """Logs flagged DNS queries to a local file and prints a terminal alert."""
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  print(f"[!] ALERT [{timestamp}]: Suspicious domain queried!")
  print(f"    -> Source IP : {ip_src}")
  print(f"    -> Domain    : {domain}\n")

  log_entry = {
      "timestamp": timestamp,
      "source_ip": ip_src,
      "domain": domain,
  }

  data = []
  if os.path.exists(LOG_FILE):
    try:
      with open(LOG_FILE, "r") as f:
        data = json.load(f)
    except json.JSONDecodeError:
      data = []

  data.append(log_entry)
  with open(LOG_FILE, "w") as f:
    json.dump(data, f, indent=4)


def process_dns_packet(packet):
  """Inspects UDP packets for DNS queries, extracting source IP and query name."""
  if packet.haslayer(DNS) and packet.haslayer(IP):
    # Check if it is a standard query (qr == 0 means query, not response)
    if packet[DNS].qr == 0 and packet.haslayer(DNSQR):
      ip_src = packet[IP].src
      try:
        # Extract and decode the queried domain name
        raw_qname = packet[DNSQR].qname
        if isinstance(raw_qname, bytes):
          domain = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
        else:
          domain = str(raw_qname).rstrip(".")

        print(f"[*] DNS Query: {ip_src} -> {domain}")

        # Check against blocklist (supports exact match or wildcard suffix matching)
        if any(
            domain == bad_domain or domain.endswith("." + bad_domain)
            for bad_domain in SUSPICIOUS_DOMAINS
        ):
          log_suspicious_dns(ip_src, domain)

      except Exception as e:
        # Fallback safeguard against malformed DNS queries
        pass


def start_dns_monitor(interface=None):
  print(
      "[*] Starting DNS query monitoring... (Listening on UDP port 53, Press"
      " Ctrl+C to stop)"
  )
  # Filter strictly for UDP port 53 (DNS traffic)
  sniff(filter="udp port 53", prn=process_dns_packet, store=False, iface=interface)


if __name__ == "__main__":
  # Run monitor (Requires root/administrator privileges for live interface sniffing)
  start_dns_monitor()

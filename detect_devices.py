from scapy.all import ARP, Ether, srp
import time

# Configuration
SUBNET = "192.168.1.0/24"  # Replace with your local subnet
TRUSTED_DEVICES = {
    "aa:bb:cc:dd:ee:ff": "Gateway Router",
    "11:22:33:44:55:66": "Admin Laptop",
    # Add other known MAC addresses here (lowercase)
}

def scan_network(subnet):
    """Sends ARP requests to the subnet and returns a list of active devices."""
    print(f"[*] Scanning subnet {subnet} for active devices...")
    
    # Create ARP request packet combined with an Ethernet broadcast
    arp_req = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    
    # Send packet and receive responses
    answered, _ = srp(packet, timeout=2, verbose=False)
    
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc.lower()})
        
    return devices

def monitor_network():
    """Continuously checks the network for unknown devices."""
    print("[*] Starting Network Rogue Device Monitor. Press Ctrl+C to stop.")
    
    while True:
        current_devices = scan_network(SUBNET)
        
        print(f"\n[+] Scan complete. Found {len(current_devices)} active device(s).")
        
        for device in current_devices:
            mac = device['mac']
            ip = device['ip']
            
            if mac in TRUSTED_DEVICES:
                print(f"    [Trusted] {ip} ({mac}) - {TRUSTED_DEVICES[mac]}")
            else:
                print(f"    [ALERT!] Unknown device detected! IP: {ip} | MAC: {mac}")
                # Optional: Trigger an alert action, log to a file, or send a webhook here.
                
        print("\n[*] Waiting 60 seconds for the next scan...")
        time.sleep(60)

if __name__ == "__main__":
    try:
        monitor_network()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")

import socket

def scan_port(target_ip, port):
    """Attempts to establish a TCP connection to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        
        # connect_ex returns 0 if the connection was successful
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        return result == 0
    except Exception:
        return False

def port_scan(target_ip, ports):
    print(f"[*] Starting port scan on target: {target_ip}")
    open_ports = []
    
    for port in ports:
        if scan_port(target_ip, port):
            print(f"    [+] Port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"    [-] Port {port} is closed or filtered")
            
    print(f"\n[+] Scan complete. Found {len(open_ports)} open port(s).")
    return open_ports

if __name__ == "__main__":
    # Use localhost or a machine you have explicit permission to test
    target = "127.0.0.1"  
    common_ports = [21, 22, 80, 443, 3306, 8080]
    
    port_scan(target, common_ports)

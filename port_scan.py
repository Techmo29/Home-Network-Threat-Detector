import argparse
import errno
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def scan_port(target, port, timeout=1.0):
    """Scan one TCP port and return its status along with service info."""
    service = "unknown"
    try:
        service = socket.getservbyport(port, "tcp")
    except (socket.error, OSError):
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

        if result == 0:
            return port, "open", service

        if result == errno.ECONNREFUSED:
            return port, "closed", service

        if result == errno.ETIMEDOUT:
            return port, "filtered/timeout", service

        return port, "error", errno.errorcode.get(result, str(result)), service

    except socket.gaierror:
        return port, "error", "hostname resolution failed", service
    except (socket.timeout, TimeoutError):
        return port, "filtered/timeout", service
    except OSError as exc:
        return port, "error", str(exc), service


def parse_ports(port_arg):
    """Parse port arguments supporting single ports, comma lists, and ranges (e.g., 80,443,1000-1024)."""
    ports = set()
    parts = port_arg.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            sub_parts = part.split("-")
            if len(sub_parts) != 2:
                raise ValueError(f"Invalid port range format: '{part}'")
            start, end = int(sub_parts[0].strip()), int(sub_parts[1].strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be integers from 1 to 65535.")
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError("Ports must be integers from 1 to 65535.")
            ports.add(p)
    return sorted(list(ports))


def port_scan(target, ports, timeout=1.0, workers=20):
    """Scan a list of TCP ports using a bounded thread pool."""
    ports = list(ports)

    if not target.strip():
        raise ValueError("Target cannot be empty.")

    if not ports:
        raise ValueError("Provide at least one port.")

    if timeout <= 0:
        raise ValueError("Timeout must be positive.")

    if workers < 1:
        raise ValueError("Workers must be at least 1.")

    print(f"[*] Scanning {target}: {len(ports)} TCP ports")
    
    start_time = time.time()
    open_ports = []
    scan_results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(
            lambda port: scan_port(target, port, timeout),
            ports,
        )

        for result in results:
            port = result[0]
            status = result[1]
            service = result[-1]
            details = result[2:-1]

            scan_results.append({
                "port": port,
                "status": status,
                "service": service,
                "details": details[0] if details else None
            })

            if status == "open":
                print(f"[+] Port {port} ({service}): OPEN")
                open_ports.append({"port": port, "service": service})
            elif status == "closed":
                print(f"[-] Port {port}: CLOSED")
            elif status == "filtered/timeout":
                print(f"[?] Port {port}: FILTERED OR TIMEOUT")
            else:
                detail = details[0] if details else "unknown error"
                print(f"[!] Port {port}: ERROR ({detail})")

    duration = time.time() - start_time
    print(f"\n[+] Scan complete: {len(open_ports)} open port(s) found in {duration:.2f} seconds.")
    
    return {
        "target": target,
        "duration_seconds": round(duration, 2),
        "open_ports": open_ports,
        "all_results": scan_results
    }


def main():
    parser = argparse.ArgumentParser(
        description="Advanced TCP port scanner for authorized testing."
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="21,22,80,443,3306,8080",
        help="Ports to scan (e.g. '80', '22,80,443', or '1-1024')",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=20,
        help="Maximum concurrent connections (default: 20)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save scan results to a JSON file path",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        report = port_scan(args.target, ports, args.timeout, args.workers)
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=4)
            print(f"[+] Results saved to {args.output}")

    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

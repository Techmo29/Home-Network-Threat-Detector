import argparse
import errno
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def grab_banner(sock, timeout=1.5):
    """Attempt to grab a service banner from an open port."""
    try:
        sock.settimeout(timeout)
        # Send a generic probe if it's a protocol like HTTP, or just wait for data
        banner = sock.recv(1024)
        decoded = banner.decode("utf-8", errors="ignore").strip()
        return decoded if decoded else None
    except (socket.timeout, socket.error, OSError):
        return None


def scan_port(target, port, timeout=1.0, grab_banners=False):
    """Scan one TCP port and return its status along with service info and banner."""
    service = "unknown"
    try:
        service = socket.getservbyport(port, "tcp")
    except (socket.error, OSError):
        pass

    banner = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

        if result == 0:
            if grab_banners:
                # Re-open briefly to grab banner if requested
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as banner_sock:
                        banner_sock.settimeout(timeout)
                        banner_sock.connect((target, port))
                        banner = grab_banner(banner_sock, timeout)
                except Exception:
                    pass
            return port, "open", service, banner

        if result == errno.ECONNREFUSED:
            return port, "closed", service, None

        if result == errno.ETIMEDOUT:
            return port, "filtered/timeout", service, None

        return port, "error", errno.errorcode.get(result, str(result)), service, None

    except socket.gaierror:
        return port, "error", "hostname resolution failed", service, None
    except (socket.timeout, TimeoutError):
        return port, "filtered/timeout", service, None
    except OSError as exc:
        return port, "error", str(exc), service, None


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


def port_scan(target, ports, timeout=1.0, workers=50, grab_banners=False, verbose=False):
    """Scan a list of TCP ports using a bounded thread pool with progress updates."""
    ports = list(ports)

    if not target.strip():
        raise ValueError("Target cannot be empty.")

    if not ports:
        raise ValueError("Provide at least one port.")

    if timeout <= 0:
        raise ValueError("Timeout must be positive.")

    if workers < 1:
        raise ValueError("Workers must be at least 1.")

    # Resolve target hostname to IP upfront
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Unable to resolve hostname: '{target}'")

    print(f"[*] Target: {target} ({target_ip})")
    print(f"[*] Scanning {len(ports)} TCP port(s) using {workers} worker threads...\n")
    
    start_time = time.time()
    open_ports = []
    scan_results = []
    completed_count = 0
    total_ports = len(ports)

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {
                executor.submit(scan_port, target_ip, port, timeout, grab_banners): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                completed_count += 1
                try:
                    result = future.result()
                    port = result[0]
                    status = result[1]
                    service = result[-2] if len(result) >= 4 else "unknown"
                    banner = result[-1] if len(result) >= 4 else None
                    details = result[2:-2] if len(result) > 4 else (result[2] if len(result) == 3 else None)

                    scan_results.append({
                        "port": port,
                        "status": status,
                        "service": service,
                        "banner": banner,
                        "details": details if isinstance(details, str) else None
                    })

                    if status == "open":
                        banner_str = f" | Banner: {repr(banner)}" if banner else ""
                        print(f"[+] Port {port} ({service}): OPEN{banner_str}")
                        open_ports.append({"port": port, "service": service, "banner": banner})
                    elif verbose:
                        if status == "closed":
                            print(f"[-] Port {port}: CLOSED")
                        elif status == "filtered/timeout":
                            print(f"[?] Port {port}: FILTERED OR TIMEOUT")
                        else:
                            print(f"[!] Port {port}: ERROR")

                except Exception as exc:
                    if verbose:
                        print(f"[!] Error scanning port: {exc}")

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user. Compiling partial results...")

    duration = time.time() - start_time
    print(f"\n[+] Scan complete: {len(open_ports)} open port(s) found in {duration:.2f} seconds.")
    
    # Sort results sequentially by port number
    scan_results.sort(key=lambda x: x["port"])
    open_ports.sort(key=lambda x: x["port"])

    return {
        "target": target,
        "target_ip": target_ip,
        "duration_seconds": round(duration, 2),
        "open_ports": open_ports,
        "all_results": scan_results
    }


def main():
    parser = argparse.ArgumentParser(
        description="Advanced, high-performance TCP port scanner for authorized network testing."
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
        default=50,
        help="Maximum concurrent worker threads (default: 50)",
    )
    parser.add_argument(
        "-b", "--grab-banners",
        action="store_true",
        help="Attempt to grab service banners on open ports",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show closed and filtered ports in output",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save scan results to a JSON file path",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        report = port_scan(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=args.grab_banners,
            verbose=args.verbose
        )
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=4)
            print(f"[+] Results successfully saved to {args.output}")

    except ValueError as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

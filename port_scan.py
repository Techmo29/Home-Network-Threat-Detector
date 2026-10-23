
import argparse
import errno
import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(target, port, timeout=1.0):
    """Scan one TCP port and return its status."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

        if result == 0:
            return port, "open"

        if result == errno.ECONNREFUSED:
            return port, "closed"

        if result == errno.ETIMEDOUT:
            return port, "filtered/timeout"

        return port, "error", errno.errorcode.get(result, str(result))

    except socket.gaierror:
        return port, "error", "hostname resolution failed"
    except (socket.timeout, TimeoutError):
        return port, "filtered/timeout"
    except OSError as exc:
        return port, "error", str(exc)


def port_scan(target, ports, timeout=1.0, workers=20):
    """Scan a list of TCP ports using a bounded thread pool."""
    ports = list(ports)

    if not target.strip():
        raise ValueError("Target cannot be empty.")

    if not ports:
        raise ValueError("Provide at least one port.")

    if any(
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("Ports must be integers from 1 to 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be positive.")

    if workers < 1:
        raise ValueError("Workers must be at least 1.")

    print(f"[*] Scanning {target}: {len(ports)} TCP ports")
    open_ports = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(
            lambda port: scan_port(target, port, timeout),
            ports,
        )

        for result in results:
            port, status, *details = result

            if status == "open":
                print(f"[+] Port {port}: OPEN")
                open_ports.append(port)
            elif status == "closed":
                print(f"[-] Port {port}: CLOSED")
            elif status == "filtered/timeout":
                print(f"[?] Port {port}: FILTERED OR TIMEOUT")
            else:
                detail = details[0] if details else "unknown error"
                print(f"[!] Port {port}: ERROR ({detail})")

    print(f"\n[+] Scan complete: {len(open_ports)} open port(s).")
    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description="Basic TCP port scanner for authorized testing."
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="21,22,80,443,3306,8080",
        help="Comma-separated TCP ports",
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

    args = parser.parse_args()

    try:
        ports = [int(value.strip()) for value in args.ports.split(",")]
        port_scan(args.target, ports, args.timeout, args.workers)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

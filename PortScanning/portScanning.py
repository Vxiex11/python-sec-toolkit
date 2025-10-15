#!/usr/bin/env python3
"""
TCP Port Scanner with optional HTTP HEAD and TLS certificate probing.

Features:
- Concurrent port scanning using ThreadPoolExecutor.
- Optional HTTP HEAD probe for ports 80/8080.
- Optional TLS handshake probe for port 443 (extracts certificate CN).
- Clean signal handling (Ctrl+C) that closes open sockets safely.
- Banner formatting that avoids printing non-printable characters (shows hex).
- CLI options for workers, timeout, disabling HEAD probes, and enabling TLS probe.

[!] WARNING: Only scan systems you own or have explicit permission to scan. [!]

[+] Program created by Vxiex11 :)
"""
import argparse
import binascii
import itertools
import signal
import socket
import ssl
import string
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Tuple, Union
from termcolor import colored

# Shared global state for open sockets and a lock to avoid races between threads
open_sockets: List[socket.socket] = []
open_sockets_lock = threading.Lock()


# ---------------------------
# Signal handler
# ---------------------------
def def_handler(sig, frame) -> None:
    """
    Signal handler for graceful shutdown (Ctrl+C).
    Closes any open sockets in a thread-safe manner and exits the program.
    """
    print(f"\n\n[+] Last signal received: {sig}")
    print(colored("[!] Leaving...", "red"))

    # Close sockets while holding the lock to avoid race conditions with worker threads
    with open_sockets_lock:
        for s in list(open_sockets):
            try:
                s.close()
            except Exception:
                pass
        open_sockets.clear()

    raise SystemExit(0)


# Register the Ctrl+C handler
signal.signal(signal.SIGINT, def_handler)


# ---------------------------
# CLI parsing
# ---------------------------
def get_arguments() -> Tuple[str, str, bool, bool, int, float]:
    """
    Parse command-line arguments.

    Returns:
        (target, port_string, send_head, probe_https, workers, timeout)
    """
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        required=True,
        help="Target to scan (e.g. '-t 192.168.1.10' or '-t example.com')",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        required=True,
        help="Ports to scan. Ranges like '1-1024', comma list '22,80,443' or single '80'.",
    )
    parser.add_argument(
        "--no-head",
        dest="no_head",
        action="store_true",
        help="Do not send HTTP HEAD probes to ports 80/8080 (default: send HEAD).",
    )
    parser.add_argument(
        "--probe-https",
        dest="probe_https",
        action="store_true",
        help="Attempt TLS handshake on port 443 and extract certificate common name (CN).",
    )
    parser.add_argument(
        "--workers",
        dest="workers",
        type=int,
        default=70,
        help="Number of concurrent worker threads (default: 70). Reduce if you hit resource limits.",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=0.7,
        help="Socket timeout in seconds (default: 0.7). Increase for slow networks.",
    )

    args = parser.parse_args()
    return args.target, args.port, not args.no_head, args.probe_https, args.workers, args.timeout


# --------------------------- #
# Socket utilities
# --------------------------- #
def create_socket(timeout: float) -> socket.socket:
    """
    Create a TCP socket, set timeout and register it in the open_sockets list.
    Returns:
        Configured socket.socket instance.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    with open_sockets_lock:
        open_sockets.append(s)
    return s

# --------------------------- #
# Banner formatting
# --------------------------- #
def format_banner(data: bytes, max_len: int = 200) -> str:
    """
    Convert raw received bytes into a human-friendly banner string.

    - Tries UTF-8 decoding first, falls back to latin-1 to preserve bytes.
    - Strips whitespace and returns the first printable line if possible.
    - If non-printable bytes are present, returns a short hex preview.

    Args:
        data: raw bytes received from the remote service.
        max_len: maximum number of bytes to consider when building the preview.

    Returns:
        A short string suitable for printing in logs.
    """
    if not data:
        return ""

    data = data[:max_len]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")

    text = text.strip()

    # If there are non-printable characters, show a hex preview instead
    if any(ch not in string.printable for ch in text):
        hexview = binascii.hexlify(data).decode("ascii")
        return f"<binary {len(data)} bytes> hex={hexview[:80]}{'...' if len(hexview) > 80 else ''}"

    # Otherwise return the first non-empty line
    lines = text.splitlines()
    return lines[0] if lines else text


# ---------------------------
# Port scanning worker
# ---------------------------
def port_scanner_main(port: int, host: str, send_head: bool, probe_https: bool, timeout: float) -> None:
    """
    Worker function executed by each thread to test a single port.

    Steps:
    1. Create and register a socket (with timeout).
    2. Attempt to connect using connect_ex.
    3. If connected, optionally:
       - Wrap socket in TLS to extract certificate (for port 443 when probe_https=True).
       - Send HTTP HEAD on ports 80/8080 (if send_head is True).
       - Otherwise send a minimal probe ('\r\n') to elicit banners.
    4. Receive up to 4096 bytes and format the banner for printing.
    5. Clean up socket and unregister it.

    Args:
        port: destination port to probe.
        host: hostname or IP to connect to.
        send_head: whether to send HTTP HEAD on 80/8080.
        probe_https: whether to attempt TLS handshake on port 443.
        timeout: socket timeout in seconds.
    """
    my_socket = None
    try:
        my_socket = create_socket(timeout)
    except Exception:
        # Could not create socket; skip this port
        return

    try:
        # connect_ex is non-raising; returns 0 on success
        rc = my_socket.connect_ex((host, port))
        if rc != 0:
            return

        response_result = ""
        try:
            # TLS probe path (port 443) - wrap the already-connected socket.
            if probe_https and port == 443:
                try:
                    context = ssl.create_default_context()
                    # wrap_socket will perform the handshake by default
                    tls_sock = context.wrap_socket(my_socket, server_hostname=host)
                    cert = tls_sock.getpeercert()
                    subject_cn = None
                    issuer_cn = None
                    if cert:
                        # 'subject' and 'issuer' are sequences of RDNs in the cert dict
                        for rdn in cert.get("subject", ()):
                            if rdn and isinstance(rdn[0], tuple) and rdn[0][0] == "commonName":
                                subject_cn = rdn[0][1]
                                break
                        for rdn in cert.get("issuer", ()):
                            if rdn and isinstance(rdn[0], tuple) and rdn[0][0] == "commonName":
                                issuer_cn = rdn[0][1]
                                break
                    response_result = f"TLS cert: subject={subject_cn} issuer={issuer_cn}"
                    # Close TLS socket explicitly
                    try:
                        tls_sock.close()
                    except Exception:
                        pass
                except Exception:
                    # TLS handshake failed or certificate not retrievable — treat as no banner
                    response_result = ""
                finally:
                    # We've either closed the wrapped socket or the TLS handshake failed.
                    # Avoid using the original socket for regular recv after wrapping.
                    pass
            else:
                # HTTP HEAD for HTTP ports (80/8080)
                if send_head and port in (80, 8080):
                    try:
                        my_socket.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    except Exception:
                        # Could fail if the server resets or isn't HTTP — ignore and continue
                        pass
                else:
                    # Minimal probe that often elicits a banner without breaking protocols
                    try:
                        my_socket.sendall(b"\r\n")
                    except Exception:
                        pass

                # Try to receive up to 4096 bytes. If it times out, treat as empty response.
                try:
                    data = my_socket.recv(4096)
                except socket.timeout:
                    data = b""

                if data:
                    response_result = format_banner(data)

        except (socket.timeout, Exception):
            response_result = ""

        # Print the result — include banner if we have one
        if response_result:
            print(colored(f"[+] Port: {port} is open - {response_result}", "green"))
        else:
            print(colored(f"[+] Port: {port} is open", "green"))

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Common network exceptions — port closed, unreachable, etc. — ignore and exit
        pass
    finally:
        # Ensure socket is closed and removed from the global list in a thread-safe way
        if my_socket:
            try:
                my_socket.close()
            except Exception:
                pass
            with open_sockets_lock:
                try:
                    open_sockets.remove(my_socket)
                except ValueError:
                    pass


# ---------------------------
# Port list parsing
# ---------------------------
def parse_ports(ports_str: str) -> Iterable[int]:
    """
    Parse the user-supplied port string and return an iterable of port integers.

    Supported forms:
        '80'           -> (80,)
        '22,80,443'    -> [22, 80, 443]
        '1-1024'       -> range(1, 1025)

    Validates ports are within 1..65535.

    Args:
        ports_str: user provided port string

    Returns:
        Iterable of port integers (range or list)

    Exits the program with an error message on invalid input.
    """
    ports_str = ports_str.strip()
    try:
        if "-" in ports_str:
            start_str, end_str = ports_str.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError("Port range invalid")
            return range(start, end + 1)
        elif "," in ports_str:
            parts = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
            for p in parts:
                if not (1 <= p <= 65535):
                    raise ValueError("Port out of range")
            return parts
        else:
            p = int(ports_str)
            if not (1 <= p <= 65535):
                raise ValueError("Port out of range")
            return (p,)
    except ValueError as ve:
        print(colored(f"[!] Invalid port specification: {ve}", "red"))
        sys.exit(1)


# ---------------------------
# Orchestrator: schedule workers
# ---------------------------
def scan_ports(target: str, ports: Iterable[int], send_head: bool, probe_https: bool, workers: int, timeout: float) -> None:
    """
    Resolve target and launch ThreadPoolExecutor to scan the given ports.

    Args:
        target: hostname or IP string
        ports: iterable of integer ports
        send_head: whether to send HTTP HEAD to 80/8080
        probe_https: whether to attempt TLS handshake on 443
        workers: number of concurrent threads
        timeout: socket timeout for each socket
    """
    try:
        # Resolve early so we can fail fast if the hostname is invalid
        host_ip = socket.gethostbyname(target)
    except Exception as e:
        print(colored(f"[!] Unable to resolve target '{target}': {e}", "red"))
        sys.exit(1)

    # Use ThreadPoolExecutor to concurrently run port workers.
    # itertools.repeat helps pass the same arguments to each worker.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(
            port_scanner_main,
            ports,
            itertools.repeat(target),
            itertools.repeat(send_head),
            itertools.repeat(probe_https),
            itertools.repeat(timeout),
        )
# ---------------------------
# Main entrypoint
# ---------------------------
def main() -> None:
    target, ports_str, send_head, probe_https, workers, timeout = get_arguments()
    ports = parse_ports(ports_str)
    scan_ports(target, ports, send_head, probe_https, workers, timeout)


if __name__ == "__main__":
    # Print a blank line for cleaner terminal output before starting
    print("")
    main()

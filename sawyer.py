import socket, time, re, sys
from concurrent.futures import ThreadPoolExecutor
# ping scan next? OS detection?

refusedports = []
closedports = []

def help():
    print("[+] Usage: python3 sawyer.py <target IP> [mode] [starting port] [ending port]")
    print("[+] mode can be '--all' for TCP and UDP scans, '--tcp' will do only TCP scans, and '--udp' will do only UDP scans.")
    print("[!] If no starting or ending port is specified, port range 1-1024 will be used!")
    sys.exit(0)

def resolveService(port, protocol):
    try:
        service = socket.getservbyport(port, protocol)
        return service
    except Exception:
        print(f"[!] An error occured while attempting to resolve port {port}'s service.")
        return "unknownm"

def tcpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    connected = False
    try:
        sock.connect((target, port))
        connected = true
        print(f"[+] {target}:{port} is open and running {resolveService(port, "tcp")}")
    except ConnectionRefusedError:
        refusedports.append(port)
    except Exception:
        closedports.append(port)
    finally:
        try:
            if connected:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError as err:
            print(f"An error occured during shutdown: {err}")
        sock.close()

def udpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.connect((target, port))
        sock.sendto(b'Hello', (target, port))
        sock.recvfrom(1024) # listen for ICMP response
        print(f"[+] {target}:{port} is open and running {resolveService(port, "udp")}")
    except ConnectionRefusedError:
        refusedports.append(port)
    except Exception:
        closedports.append(port)
    finally:
        # no need to shutdown since UDP is connectionless; no connection to shutdown really
        sock.close()

# create scanning threads and go
def main(target, start, end, mode):
    print("Sawyer v1.0.0 by nubb (nubbsterr). A multithreaded port scanner written in Python.")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for port in range(start, end + 1):
            if mode == "udp":
                futures.append(executor.submit(udpScan, target, port))
            elif mode == "tcp":
                futures.append(executor.submit(tcpScan, target, port))
            elif mode == "both":
                futures.append(executor.submit(tcpScan, target, port))
                futures.append(executor.submit(udpScan, target, port))
        # Wait for all tasks to complete
        for future in futures:
            future.result()

    end_time = time.time()
    closedports.sort()
    refusedports.sort()
    print(f"[+] Scan complete. Took {end_time - start_time} seconds. Scanned {(end - start) + 1} ports.")
    print(f"[+] Closed ports: {closedports}")
    print(f"[+] Refused ports: {refusedports}")

# verify that passed arguments are valid before scanning
def args():
    if "help" in sys.argv:
        help()

    if (len(sys.argv) < 2) or (not re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", sys.argv[1])):
        print("[x] Specify an IPv4 address! No domains or IPv6 trash pls and thx.")
        help()
    
    mode = "tcp"
    if "--tcp" in sys.argv:
        mode = "tcp"
    elif "--udp" in sys.argv:
        mode = "udp"
    elif "--all" in sys.argv:
        mode = "both"

    start, end = 1, 1024
    # are all arguments supplied
    if len(sys.argv) >= 4:
        start = int(sys.argv[2])
        end = int(sys.argv[3])
        if not (1 <= start <= end <= 65535):
            print(f"[!] Invalid port range. Port range must be between 1 and 65535. Using default range 1-1024.")
            start, end = 1, 1024
    else:
        print(f"[!] Invalid port range. Port range must be between 1 and 65535. Using default range 1-1024.")
        start, end = 1, 1024
    main(sys.argv[1], start, end, mode)

args()

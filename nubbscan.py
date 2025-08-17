import socket, sys, subprocess, threading
from time import time
from re import match, search
from concurrent.futures import ThreadPoolExecutor
# tabulate build broke so none of that lol

# threading.Lock() is made to prevent race conditions w/ workers appending to list with no synchronization, resulting in lost data or corruption
openports = []
openports_lock = threading.Lock()

refusedports = []
refusedports_lock = threading.Lock()

# ascii escape codes for colour
RED = '\033[31m'
GREEN = '\033[32m'
RESET = '\033[0m'
YELLOW = '\033[33m'
#BLUE = '\033[34m'

def help():
    print("Usage: python3 nubbscan.py target [starting port [ending port] [--udp]")
    print("--udp: Perform UDP scans. Experimental feature. By default, TCP scans are performed.\n")
    print("If no starting or ending port is specified, port range 1-1024 will be used!")
    print("Nubbscan automatically scans 2049, 3389 and 5985, provided the port range is lower/greater than said ports.")
    sys.exit(0)

def resolveService(port, protocol):
    try:
        service = socket.getservbyport(port, protocol)
        return service
    except Exception:
        print(f"{YELLOW}[-] An error occurred while attempting to resolve port {port}'s service.{RESET}")
        return "Unknown service"

def tcpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    # surely a better way to implement this but ugh
    try:
        isOpen = sock.connect_ex((target, port))
        if isOpen == 0:
            with openports_lock:
                openports.append([port, resolveService(port, "tcp")])
    except ConnectionRefusedError:
        # Port was refused or in a filtered state
        with refusedports_lock:
            refusedports.append([port, resolveService(port, "tcp")])
    except Exception:
        pass # Connection failed/timeout
    finally:
        sock.close()

def udpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.connect((target, port))
        sock.sendto(b'Hello', (target, port))
        sock.recvfrom(1024) # listen for ICMP response
        with openports_lock:
            openports.append([port, resolveService(port, "udp")])
    except ConnectionRefusedError:
        pass # Port was refused or in a filtered state
        with refusedports_lock:
            refusedports.append([port, resolveService(port, "udp")])
    except Exception:
        pass # Connection failed/timeout
    finally:
        # no need to shutdown since UDP is connectionless
        sock.close()

def OSdetection(target, pingout):
# get TTL from ping output to get very lazy and experimental OS detection
    print(f"{YELLOW}[!] OS detection is based on TTL. This is totally reliant on TTL not being altered by other network devices or system configurations.")
    ttlmatch = search(r"ttl=(\d+)", pingout.lower())
    ttl = int(ttlmatch.group(1))

    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Solaris/Unix"

    return f"Unknown Operating system, TTL: {ttl}"

def isHostUp(target):
    result = subprocess.run(["ping", "-c", "1", target], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if result.returncode == 0:    
        print(f"{GREEN}[+] Host ({target}) is up!{RESET}")
        print(f"{GREEN}[+] Operating system is: {OSdetection(target, result.stdout)}{RESET}\n")
    else:
        print(f"{RED}[x] Host ({target}) is down. Check your network/VPN connections.){RESET}\n")
        sys.exit(1)

def resolveTarget(target):
    ip_match = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if match(target, ip_match):
        return target # an IPv4 address

    try:
        ipv4 = socket.gethostbyname(target)
        print(f"{GREEN}[+] Resolved {target} to {ipv4}.{RESET}")
        return ipv4
    except socket.gaierror:
        print(f"{RED}[x] Could not resolve {target}. Check the hostname in your /etc/hosts file, or other network connections.{RESET}")
        sys.exit(1)

# create scanning threads and go
def main(target, start, end, mode):
    print(f"\n{GREEN}[+] Nubbscan v2.2.0 by nubb (nubbsterr). A multithreaded port scanner written in Python.{RESET}")
    print(f"{GREEN}[+] Scanning {target}. First confirming if host is live...{RESET}")
    isHostUp(target)

    start_time = time()
    extraports = [2049, 3389, 5985, 8080] # NFS, RDP, WinRM, HTTP-alt
    ports = list(range(start, end + 1)) + [port for port in extraports if (port < start) or (port  > end)]

    workers = min(100, max(10, len(ports) // 20)) # max of 100 workers or min of 10, adjust to port range
    print(f"{GREEN}[+] Using {workers} workers for {len(ports)} ports.{RESET}")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        if mode == "udp":
            for port in ports:
                futures.append(executor.submit(udpScan, target, port))
        else:
            for port in ports:
                futures.append(executor.submit(tcpScan, target, port))

        # Wait for all tasks to complete
        for future in futures:
            future.result()

    end_time = time()
    print(f"{GREEN}[+] Scan complete. Took {round(end_time - start_time, 2)} seconds. Scanned {len(ports)} ports.{RESET}\n")
    sortedopen = sorted(openports)
    sortedrefused = sorted(refusedports)
    # very iffy but it works lol, tabulate broken
    print(f"{GREEN}Open ports:{RESET}")
    for port, service in sortedopen:
        print(f"Port {port}: {service}")
    print(f"\n{RED}Refused/filtered ports:{RESET}")
    for port, service in sortedrefused:
        print(f"Port {port}: {service}")

# verify that passed arguments are valid before scanning
def args():
    if "help" in sys.argv:
        help()

    if (len(sys.argv) < 2):
        print(f"{RED}[x] Specify an IPv4 address or domain name!{RESET}")
        help()
    
    target = resolveTarget(sys.argv[1])
    
    mode = "tcp"
    if "--udp" in sys.argv:
        mode = "udp"
    
    start, end = 1, 1024
    # are all arguments supplied
    if len(sys.argv) >= 4:
        try:
            start = int(sys.argv[2])
            end = int(sys.argv[3])
            if not (1 <= start <= end <= 65535):
                print(f"{YELLOW}[-] Invalid port range. Port range must be between 1 and 65535. Using default range 1-1024.{RESET}")
                start, end = 1, 1024
        except Exception as err:
            print(f"{YELLOW}[-] An exeception occurred when evaluating port range. Using default range 1-1024. Error: {RESET}{err}")
            start, end = 1, 1024
    else:
        print(f"{YELLOW}[-] No port range was given. Using default range 1-1024.{RESET}")
        start, end = 1, 1024
    main(target, start, end, mode)

args()

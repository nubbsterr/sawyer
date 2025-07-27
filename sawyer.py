import socket, sys, subprocess, threading
from time import time
from re import match
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate 

# openports_lock made to prevent race conditions w/ workers appending to list with no synchronization, resulting in lost data or corruption
openports = []
openports_lock = threading.Lock()

def help():
    print("[+] Usage: python3 sawyer.py <target IP> [starting port] [ending port] [--udp] [--debug]")
    print("[+] --udp: Perform UDP scans. Experimental feature. By default, TCP scans are performed.")
    print("[!] If no starting or ending port is specified, port range 1-1024 will be used!")
    sys.exit(0)

def resolveService(port, protocol):
    try:
        service = socket.getservbyport(port, protocol)
        return service
    except Exception:
        print(f"[!] An error occured while attempting to resolve port {port}'s service.")
        return "Unknown service"

def tcpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
	# surely a better way to implement this but ugh
    try:
        isOpen = sock.connect_ex((target, port))
		if isOpen:
        	with openports_lock:
				openports.append([port, resolveService(port, "tcp")])
    except ConnectionRefusedError:
        pass # Port was refused or in a filtered state
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
    except Exception:
        pass # Connection failed/timeout
    finally:
        # no need to shutdown since UDP is connectionless
        sock.close()

def isHostUp(target):
    if subprocess.run(["ping", "-c", "1", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        print(f"[+] Host ({target}) is up!\n")
    else:
        print(f"[+] Host ({target}) is down. Check your network connections.)\n")
        sys.exit(1)

# create scanning threads and go
def main(target, start, end, mode):
    print("Sawyer v2.0.0 by nubb (nubbsterr). A multithreaded port scanner written in Python.")
    print(f"[+] Scanning {target}. First confirming if host is live...\n")
    isHostUp(target)

    start_time = time()
	extraports = [2049, 3389, 5985] # NFS, RDP, WinRM
	ports = list(range(start, end + 1)) + [extraport in extraports if (extraport < start) or (extraport > end)]

	workers = min(100, max(10, len(ports) // 10)) # max of 100 workers or min of 10, adjust to port range
	print(f"[+] Using {workers} workers for {len(ports)}.")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
		if mode == "udp":
			for port in ports:
				futures.append(executor.submit(udpScan, target, port))
		if mode == "tcp":
			for port in ports:
				futures.append(executor.submit(tcpScan, target, port))

        # Wait for all tasks to complete
        for future in futures:
            future.result()

    end_time = time()
    print(f"[+] Scan complete. Took {round(end_time - start_time, 2)} seconds. Scanned {len(ports)} ports.\n")
    sortedopen = sorted(openports)
    print(tabulate(sortedopen, headers=['Port', 'Service']))

# verify that passed arguments are valid before scanning
def args():
    if "help" in sys.argv:
        help()

    if (len(sys.argv) < 2) or (not match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", sys.argv[1])):
        print("[x] Specify an IPv4 address! No domains or IPv6 trash pls and thx.")
        help()
    
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
            	print(f"[!] Invalid port range. Port range must be between 1 and 65535. Using default range 1-1024.")
            	start, end = 1, 1024
		except Exeception as err:
			print(f"[!] An exeception occured when evaluating port range. Using default range 1-1024.")
			start, end = 1, 1024
    else:
        print(f"[!] No port range was given. Using default range 1-1024.")
        start, end = 1, 1024
    main(sys.argv[1], start, end, mode)

args()

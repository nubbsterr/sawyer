import socket, threading, time, re, sys
# ping scan next? OS detection?

def help():
    print("Usage: python3 sawyer.py [target IP] [starting port] [ending port]")
    print("If no starting or ending port is specified, port range 1-1024 will be used!")
    sys.exit(0)

def resolveService(port, protocol):
    try:
        service = socket.getservbyport(port, protocol)
        return service
    except Exception as err:
        print(f"[!] An error occured while attempting to resolve port {port}'s service.")
        print(f"[!] Error recorded: {err}")

def tcpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((target, port))
        print(f"[+] {target}:{port} is open and running {resolveService(port, "tcp")}")
    except socket.TimeoutError:
        print(f"[-] {target}:{port} is closed. Connection timeout.")
    except OSError.ConnectionError.ConnectionRefusedError as err:
        print("[!] Connection to this port was refused. Port is in ignored state or some other state that is preventing connectivity!")
        print("[!] Your network is most likely blocking scan traffic to endpoints.")
    finally:
        # stop receiving or sending data and close
        sock.shutdown(SHUT_RDWR)
        sock.close()

def udpScan(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.connect((target, port))
        sock.sendto(b'Hello', (target, port))
        sock.recvfrom(1024) # listen for ICMP response
        print(f"[+] {target}:{port} is open and running {resolveService(port, "udp")}")
    except socket.TimeoutError:
        print(f"[-] {target}:{port} is closed. Connection timeout.")
    except OSError.ConnectionError.ConnectionRefusedError as err:
        print("[!] Connection to this port was refused. Port is in ignored state or some other state that is preventing connectivity!")
        print("[!] Your network is most likely blocking scan traffic to endpoints.")
    finally:
        # stop receiving or sending data and close
        sock.shutdown(SHUT_RDWR)
        sock.close()

# create scanning threads and go
def main(target, start, end):
    print("Sawyer v1.0.0 by nubb (nubbsterr). A multithreaded port scanner written in Python.")
    start_time = time.time()
    threads = []
    for port in range(start, end + 1):
        tcp_thread = threading.Thread(target=tcpScan, args=(target, port))
        threads.append(tcp_thread)
        tcp_thread.start()

        udp_thread = threading.Thread(target=udpScan, args=(target, port))
        threads.append(udp_thread)
        udp_thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()
    end_time = time.time()
    print(f"[+] Scan complete. Took {end_time - start_time} seconds")

# verify that passed arguments are valid before scanning
def args():
    try:
        # most painful regex match i have ever had the displeasure to see
        if re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", sys.argv[1]):
            pass
        else:
            print("[x] Specify an IPv4 address! No domains or IPv6 trash pls and thx.")
            help()
    except IndexError:
        print("[x] No target IP was specified!")
        help()

    try:
        if (int(sys.argv[2]) >= 1) and (int(sys.argv[1]) < 65535):
            pass
        else:
            print("[!] No proper port range was supplied. Ports 1-1024 will be scanned by default!")
        if (int(sys.argv[3] >= 2)) and (int(sys.argv[3] <= 65535)):
            pass
        else:
            print("[!] No proper port range was supplied. Ports 1-1024 will be scanned by default!")
    except IndexError:
        print("[!] No proper port range was supplied. Ports 1-1024 will be scanned by default!")

args()

import socket, threading, time, re, sys
# run sock.shutdown(SHUT_RDWR) before close() on sockets to fully close connection; disallow sending/receiving
# run sock.close() when scan functions are done
# have exception if socket.TimeoutError occurs, return false on scan function, showing port is closed
# for open ports, determine service running given port number and protocol; tpc or udp

def help():
    print("Usage: python3 sawyer.py [target IP] [starting port] [ending port]")
    print("If no starting or ending port is specified, port range 1-1024 will be used!")
    sys.exit(0)

def printResults():
    pass

def resolveService(port, protocol):
    pass

def tcpScan(target, port):
    pass
    # AP_INET, SOCK_STREAM
    # sock.settimeout(1)
    # sock.connect(ip, target port)
    # send SYN, if SYN-ACK is returned then the port is open, duh
    # sock.shutdown(SHUT_RDWR) and close() to stop conncetion

def udpScan(target, port):
    pass
    # AP_INET, SOCK_DGRAM
    # sock.connect(ip, target port)
    # sock.send(b'Hello', (target ip, target port)), sock.recvfrom(1024); receive max 1024 bytes from response
    # if timeout occurs, then there was no response, so port is closed
    # send UDP packet, if closed, then port unreachable should be sent back, otherwise we can assume it's open

# create scanning threads and go
def main(target, start, end):
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
        if (int(sys.argv[2] >= 2)) and (int(sys.argv[2] <= 65535)):
            pass
        else:
            print("[!] No proper port range was supplied. Ports 1-1024 will be scanned by default!")
    except IndexError:
        print("[!] No proper port range was supplied. Ports 1-1024 will be scanned by default!")

args()

import socket
import ssl
import threading
from queue import Queue
import logging
import argparse
import platform

logging.basicConfig(filename="scan_results.log", level=logging.INFO, format="%(asctime)s - %(message)s")

class PortScanner:
    def __init__(self, target_IP, start_port, end_port, thread_count=100):
        self.target_IP = target_IP.strip()
        self.start_port = start_port
        self.end_port = end_port
        self.thread_count = thread_count
        self.queue = Queue()
        self.resolved_ip = self.resolve_target()

    def resolve_target(self):
        if self.is_valid_ip(self.target_IP):
            return self.target_IP
        try:
            return socket.gethostbyname(self.target_IP)
        except socket.gaierror:
            print(f"[!] Error: Unable to resolve hostname {self.target_IP}")
            exit(1)

    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def detect_os(self):
        try:
            ttl = socket.gethostbyname(self.target_IP)
            print(f"[*] TTL Guess: {ttl}")
            print(f"[*] Host OS Guess: {platform.system()} {platform.release()}")
        except Exception:
            print("[!] OS Detection failed.")

    def banner_grab(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            if sock.connect_ex((self.resolved_ip, port)) == 0:
                print(f"[+] Port {port}: OPEN")
                logging.info(f"Port {port} OPEN")

                if port in [443, 8443, 993, 995, 465, 587]:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=self.target_IP) as ssock:
                        banner = ssock.recv(1024).decode(errors="ignore").strip()
                else:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()

                if banner:
                    print(f"    └─ Banner: {banner}")
                    logging.info(f"Banner for port {port}: {banner}")
                    if "vsftpd 2.3.4" in banner:
                        print("    🔥 VULNERABLE: CVE-2011-2523 (vsftpd backdoor)")
                    elif "Apache/2.2.8" in banner:
                        print("    🔥 VULNERABLE: CVE-2007-5000 (Apache DoS)")
                else:
                    print("    └─ No banner received.")
            sock.close()
        except Exception:
            pass

    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.banner_grab(port)
            self.queue.task_done()

    def run(self):
        print(f"\n🌐 Scanning {self.resolved_ip} from port {self.start_port} to {self.end_port} using {self.thread_count} threads.")
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.detect_os()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Banner Grabbing, Logging, and OS Detection")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use")
    args = parser.parse_args()

    try:
        scanner = PortScanner(args.target, args.start_port, args.end_port, args.threads)
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

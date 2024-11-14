#Developed by pyhacker01
#If you are copying the code, please give credit.
import time
import threading
import subprocess
import platform
import clamd
import pywifi
from pywifi import const
import webbrowser
import os
import sys
import requests
from colorama import Fore, Style, init
from scapy.all import ARP, Ether, srp, sniff, TCP, UDP, IP, send, get_if_list
import logging
import re
import nmap  
from pyngrok import ngrok
import bluetooth

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)
print(Fore.BLUE+"Login..")
user = input(Fore.GREEN + "Enter the Username: ")

while True:
    user_mail = input(Fore.GREEN + "Enter your Email: ")
    if is_valid_email(user_mail):
        print("Loading.....")
        time.sleep(8)
        break
    else:
        print(Fore.RED + "Invalid email format. Please try again.")

def show_banner():
    banner = r"""  
                 ____  __.___.____    .____     _____________________         ___.                   
                |    |/ _|   |    |   |    |    \_   _____/\______   \        \_ |__   ____   ____   
                |      < |   |    |   |    |     |    __)_  |       _/  ______ | __ \_/ __ \_/ __ \  
                |    |  \|   |    |___|    |___  |        \ |    |   \ /_____/ | \_\ \  ___/\  ___/  
                |____|__ \___|_______ \_______ \/_______  / |____|_  /         |___  /\___  >\___  > 
                        \/           \/       \/        \/         \/              \/     \/     \/  

                                 Developer:-Abhishek|version-1.0|By:-pyhacker01
                                                                                                                 """
    print(Fore.YELLOW + banner + Style.RESET_ALL)
    
def is_termux():
    return os.path.exists("/data/data/com.termux/files/home")

def start_clamd_in_termux():
    if is_termux():
        os.system("clamd &")  
        print("ClamAV daemon started in Termux.")

def clear_terminal():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
        
def scan_specific_file():
    try:
        file_path = input("Enter the path of the file to scan: ")
        system = platform.system()
        if is_termux():
            start_clamd_in_termux()
            cd = clamd.ClamdUnixSocket()
        elif system == "Linux" or system == "Darwin":
            cd = clamd.ClamdUnixSocket()
        elif system == "Windows":
            cd = clamd.ClamdNetworkSocket(host='localhost', port=3310)
        else:
            print("Unsupported OS.")
            return
        print(f"Starting scan on {file_path}...")
        result = cd.scan_file(file_path)
        if not result:
            print("No virus found in the file.")
        else:
            for file, status in result.items():
                print(f"{file}: {status[1]}")
                if status[0] == 'FOUND':
                    print(f"Virus detected in {file}: {status[1]}")
        print("File scan completed.")
    except Exception as e:
        print(f"Error: {e}")
        print("Ensure that ClamAV daemon is running and reachable.")

def full_system_scan():
    try:
        system = platform.system()
        if is_termux():
            start_clamd_in_termux()
            cd = clamd.ClamdUnixSocket()
            root_path = "/"
        elif system == "Linux" or system == "Darwin":
            cd = clamd.ClamdUnixSocket()
            root_path = "/"
        elif system == "Windows":
            cd = clamd.ClamdNetworkSocket(host='localhost', port=3310)
            root_path = "C:\\"
        else:
            print("Unsupported OS.")
            return
        print(f"Starting full system scan on {root_path}...")
        result = cd.scan(root_path)
        if not result:
            print("No virus found on the system.")
        else:
            for file, status in result.items():
                print(f"{file}: {status[1]}")
                if status[0] == 'FOUND':
                    print(f"Virus detected in {file}: {status[1]}")
        print("Full system scan completed.")
    except Exception as e:
        print(f"Error: {e}")
        print("Ensure that ClamAV daemon is running and reachable.")


def scan_wifi():
    print(Fore.RED + "Scanning for Wi-Fi networks...")
    time.sleep(2)
    
    if platform.system() == "Windows":
        result = subprocess.run(["netsh", "wlan", "show", "network", "mode=bssid"], capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)
        
    elif platform.system() == "Linux":
        result = subprocess.run(["nmcli", "device", "wifi", "list"], capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)

    elif platform.system() == "Darwin":  
        result = subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"], capture_output=True, text=True)
        print(Fore.CYAN + result.stdout)

    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(2)
        results = iface.scan_results()
        print(Fore.CYAN + "Nearby WiFi Networks:")
        for network in results:
            print(Fore.GREEN + f"SSID: {network.ssid} | MAC: {network.bssid} | Signal: {network.signal} dBm")         
    except Exception as e:
        print(Fore.RED + f"An error occurred while scanning Wi-Fi networks: {e}")

def scan_bluetooth_devices():
    print("Scanning for nearby Bluetooth devices...")
    nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True, lookup_class=False)
    
    if nearby_devices:
        print(f"Found {len(nearby_devices)} devices.")
        for addr, name in nearby_devices:
            print(f"Device: {name}, Address: {addr}")
    else:
        print("No Bluetooth devices found.")

def scan_ip_addresses(network):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments='-p 1-65535 -T5')  
    except nmap.PortScannerError as e:
        print(Fore.RED + f"PortScannerError: {e}")
        return []
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")
        return []
    
    active_ips = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            active_ips.append(host)
            print(Fore.GREEN + f"Nmap scan report for {host} ({nm[host].hostname()})")
            print(Fore.GREEN + f"Host is {'up'}.")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].items()
                for port, port_info in ports:
                    print(Fore.YELLOW + f"PORT: {port}/tcp STATE: {port_info['state']} SERVICE: {port_info.get('name', 'unknown')}")
    return active_ips

def validate_phone_number(api_key, phone_number):
    url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("valid"):
            print(Fore.GREEN + f"Phone number: {data.get('number')} is valid.")
            print(Fore.GREEN + f"Country: {data.get('country_name')}")
            print(Fore.GREEN + f"Location: {data.get('location')}")
            print(Fore.GREEN + f"Carrier: {data.get('carrier')}")
            print(Fore.GREEN + f"Line Type: {data.get('line_type')}")
        else:
            print(Fore.RED + f"Phone number: {phone_number} is not valid.")
    else:
        print(Fore.RED + f"Error: Unable to validate phone number. Status code: {response.status_code}")

def get_ip_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        print(Fore.RED + f"IP Address: {data.get('ip')}")
        print(Fore.GREEN + f"City: {data.get('city')}")
        print(Fore.BLUE + f"Region: {data.get('region')}")
        print(Fore.CYAN + f"Country: {data.get('country')}")
        print(Fore.MAGENTA + f"ISP: {data.get('org')}")
        print(Fore.YELLOW + f"Location: {data.get('loc')}")
    else:
        print(Fore.RED + f"Error: {response.status_code} - {response.text}")

def create_ngrok_tunnel(port, authtoken):
    ngrok.set_auth_token(authtoken)
    public_url = ngrok.connect(port, options={"region": "in"})  
    print(Fore.GREEN + f"Ngrok tunnel opened at {public_url}")
    return public_url

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        logging.info(Fore.GREEN + f"Packet: {src_ip} -> {dst_ip} | Protocol: {proto}")

        if packet.haslayer(TCP):
            logging.info(Fore.GREEN + f"TCP Packet: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            logging.info(Fore.GREEN + f"UDP Packet: {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}")

def start_sniffing(interface):
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nMonitoring stopped.")

def send_spoofed_packet(target_ip, spoofed_ip):
    ip = IP(src=spoofed_ip, dst=target_ip)
    tcp = TCP(sport=12345, dport=80, flags="S")
    packet = ip / tcp
    send(packet, verbose=False)
    print(Fore.GREEN + f"Sent packet from {spoofed_ip} to {target_ip}")

def generate_spoofed_ips(base_ip, count):
    base_parts = base_ip.split('.')
    for i in range(count):
        spoofed_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i % 256}"
        yield spoofed_ip  

def show_menu():
    print(Fore.YELLOW + "\nMenu")
    print(Fore.BLUE + "1 - Scan Virus")
    print(Fore.BLUE + "2 - Scan File Only")
    print(Fore.BLUE + "3 - Scan Wi-Fi")
    print(Fore.BLUE + "4 - Bluetooth scan")
    print(Fore.BLUE + "5 - Scan IP(Nmap)")
    print(Fore.BLUE + "6 - Phone Number & IP Information")
    print(Fore.BLUE + "7 - Network Sniffing")
    print(Fore.BLUE + "8 - IP Spoofer")
    print(Fore.BLUE + "9 - Ngrok(Port Forwarding)")
    print(Fore.BLUE + "10 - Exit")
    print(Fore.BLUE + "11 - Help!!")

clear_terminal()
show_banner()
init(autoreset=True)
api_key = 'your_api_key_here'  # Use your own API key.
url = "https://www.instagram.com/code_dreamerr_"
url_a = "https://whatsappcom/channel/0029VauW58x6GcGNfEXoZx41"

while True:  
    show_menu()  
    try:
        choice = int(input(Fore.GREEN + "Enter your choice: "))
        if choice == 1:
            print("Please wait!!")
            time.sleep(6)
            full_system_scan() 
            
        elif choice == 2:
            time.sleep(6)
            scan_specific_file()  

        elif choice == 3:
            time.sleep(4)
            print(Fore.RED+"Currently not working in Termux")
            time.sleep(8)
            scan_wifi()
            print(Fore.RED + "Note: The information provided may not be accurate.")
        elif choice == 4:
            time.sleep(5)
            scan_bluetooth_devices()
            
        elif choice == 5:
            print(Fore.RED+"NOTE - Require administrative privilege")
            target = input(Fore.RED + "Enter target IP or subnet (e.g., 192.168.1.0/24): ")
            print(Fore.GREEN + f"Scanning network: {target}")
            active_ips = scan_ip_addresses(target)
            print(Fore.RED + "Active IPs and their open ports:")
            for ip in active_ips:
                print(Fore.YELLOW + ip) 

        elif choice == 6:
            while True:
                try:
                    print(Fore.BLUE + "Select an option:")
                    print(Fore.BLUE + "1 - Get Phone Number Info.")
                    print(Fore.BLUE + "2 - Get IP Information")
                    print(Fore.BLUE + "3 - Exit")
                    sub_choice = int(input(Fore.GREEN + "Enter your option: "))

                    if sub_choice == 1:
                        country_code = input(Fore.GREEN + "Enter your country code (e.g., +91 for India): ")
                        phone_number = input(Fore.GREEN + "Enter your phone number: ")
                        full_phone_number = country_code + phone_number
                        validate_phone_number(api_key, full_phone_number)
                        print(Fore.RED + "Note: The information provided may not be accurate.")

                    elif sub_choice == 2:
                        print(Fore.RED+"")
                        ip_address = input(Fore.GREEN + "Enter the IP address (e.g., 8.8.8.8): ")
                        get_ip_info(ip_address)
                        print(Fore.RED + "Note: The information provided may not be accurate.")

                    elif sub_choice == 3:
                        print("Exiting...")
                        break
                    else:
                        print(Fore.RED + "Invalid choice.")
                except ValueError:
                    print(Fore.RED + "Invalid input. Please enter a valid number.")

        elif choice == 7:
            print(Fore.YELLOW+"Require administrative privilege")
            print(Fore.CYAN + "Starting Network Sniffing...")
            time.sleep(7)
            interfaces = get_if_list()
            print(Fore.LIGHTBLUE_EX + "Available interfaces:")
            for i, iface in enumerate(interfaces):
                print(Fore.LIGHTYELLOW_EX + f"{i}: {iface}")
            while True:
                choice = input(Fore.GREEN + "Select an interface (default is first :): ")
                if choice.strip() == "":
                    selected_interface = interfaces[0]
                    break
                elif choice.isdigit() and 0 <= int(choice) < len(interfaces):
                    selected_interface = interfaces[int(choice)]
                    break
                elif choice.lower() == 'exit':
                    print(Fore.RED + "Exiting network sniffing mode.")
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please select a valid interface number.")

            if 'selected_interface' in locals():
                print(Fore.GREEN + f"Starting to sniff all traffic on {selected_interface}...")
                sniff_thread = threading.Thread(target=start_sniffing, args=(selected_interface,))
                sniff_thread.start()
                print(Fore.YELLOW + "Monitoring all network traffic... Press Ctrl+C to stop.")
                try:
                    while True:
                        time.sleep(1)  
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\nMonitoring stopped.")

        elif choice == 8:
            print(Fore.RED+"Require administrative privilege")
            print(Fore.CYAN + "Starting IP spoofer..")
            time.sleep(7)
            target_ip = input(Fore.CYAN + "Enter target IP: ")
            base_spoofed_ip = input(Fore.CYAN + "Enter spoofed IP (e.g., 192.168.1.0): ")
            count = int(input(Fore.LIGHTRED_EX + "Enter the number of spoofed IP: "))
            for spoofed_ip in generate_spoofed_ips(base_spoofed_ip, count):
                send_spoofed_packet(target_ip, spoofed_ip)

        elif choice == 9:
            time.sleep(6)
            print(Fore.YELLOW+"Starting Tunneler..")
            time.sleep(6)
            port = int(input(Fore.GREEN + "Enter the port to open the Ngrok tunnel (e.g., 5000): "))
            authtoken = input(Fore.GREEN + "Enter your ngrok authtoken: ")
            try:
                create_ngrok_tunnel(port, authtoken)
            except Exception as e:
                print(Fore.RED + f"An error occurred: {e}")

        elif choice == 10:
            time.sleep(3)
            print(Fore.YELLOW + f"Enjoy your day, {user}! If you like💖 my tool, please give it a star⭐ and share it with your friends!😉")
            time.sleep(10)
            print(Fore.RED + "Exiting...👋")
            webbrowser.open(url_a)
            break

        elif choice == 11:
            print(Fore.GREEN + "Feel free to DM me with any queries🙂")
            time.sleep(3)
            webbrowser.open(url)
        else:
            print(Fore.RED + "❗Invalid choice.")

    except ValueError:
        print(Fore.RED + "❕Invalid input. Please enter a valid number.")

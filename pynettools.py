import requests
import colorama
from colorama import init, Fore, Style
import socket
import nmap
import whois
import os
import platform
import subprocess
from scapy.all import IP, TCP, sr1
import whois.whois


def clear_screen():
    os.system("clear || cls")
clear_screen()


def ipapi():
    ip = input("Enter an IP: ")

    api = f"https://ipapi.co/{ip}/json/"

    response = requests.get(api)
    if response.status_code == 200:
        data = response.json()

        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} IP: {ip}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Country: {data.get('country_name', 'N/A')}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} City: {data.get('city', 'N/A')}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Region: {data.get('region', 'N/A')}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Postal Code: {data.get('postal', 'N/A')}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Telephone Prefix: {data.get('country_calling_code', 'N/A')}")



def get_dns_ip():
    web = input("Enter a DNS: ")
    domain = f"{web}"

    contador = 0

    try:
        ips = socket.gethostbyname_ex(domain)
        for ip in ips[2]:
            contador = contador+1
            print(f"{Fore.YELLOW}[{Fore.RESET}{contador}{Fore.YELLOW}]{Fore.RESET} IP: {ip}")

        api = f"https://ipapi.co/{ip}/json/"

        response = requests.get(api)
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Country: {data.get('country_name', 'N/A')}")
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} City: {data.get('city', 'N/A')}")
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Region: {data.get('region', 'N/A')}")
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Postal Code: {data.get('postal', 'N/A')}")
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Telephone Prefix: {data.get('country_calling_code', 'N/A')}")
    except socket.gaierror:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} Please Enter an valid web or domain")



def scanner():
    ip_target = input("IP to scan: ")
    port_range = input("Port range (example 1-20): ")

    nm = nmap.PortScanner()

    try:
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Scanning {port_range} ports for: {ip_target}")

        scan_results = nm.scan(ip_target, f'{port_range}')

        host_status = scan_results['scan'][ip_target]['status']['state']
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Host status is: {host_status}")

        for proto in nm[ip_target].all_protocols():
            print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Protocol: {proto}")
            ports = nm[ip_target][proto].keys()
            for port in sorted(ports):
                port_status = nm[ip_target][proto][port]['state']
                service_name = nm[ip_target][proto][port]['name']
                print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Port {port}: {port_status} - Service: {service_name}")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has occurred: {e}")



def whois_look():
    domain = input("Input a domain to get info: ")
    try:
        info = whois.whois(domain)

        creation_date = info.get('creation_date', "N/A")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        name_servers = info.get('name_servers', [])
        if name_servers:
            name_servers = f'\n{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Name Servers: '.join(name_servers)
        else:
            name_servers = "N/A"

        emails = info.get('emails', [])
        if isinstance(emails, list):
            emails = f'\n{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Emails: '.join(emails) 

        city = info.get('city', "N/A")
        state = info.get('state', "N/A")
        registrant_postal_code = info.get('registrant_postal_code', "N/A")

        address = info.get('address', ["N/A"])
        if isinstance(address, list) and len(address) > 1:
            address = address[1]
        else:
            address = address[0] if address else "N/A"

        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Creation date: {creation_date}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Name Servers: {name_servers}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Emails: {emails}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} City: {city}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} State: {state}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Postal Code: {registrant_postal_code}")
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} Address: {address}")
    except Exception as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has occurred: {e}")



def ping_test():
    ip = input("Enter an IP to test conectivity: ")
    current_os = platform.system()
    if current_os == "Windows":
        command = ['ping', '-n', '1', ip]
    else:
        command = ['ping', '-c', '1', ip]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} You have conectivity for: {ip}")
    else:
        print(f"{Fore.YELLOW}[{Fore.RESET}+{Fore.YELLOW}]{Fore.RESET} You have no connectivity")



def select_option(option):
    actions = {
        1: scanner,
        2: ipapi,
        3: get_dns_ip,
        4: whois_look,
        5: ping_test
    }
    if option in actions:
        actions[option]()



def try_again():
    try_another = input(f"Try another time (y/n): ")
    if try_another=='y':
        main_menu()



def main_menu():
    clear_screen()
    logo = f"""{Fore.LIGHTRED_EX}
 /$$$$$$$            /$$   /$$             /$$  /$$$$$$$$                  /$$          
| $$__  $$          | $$$ | $$            | $$ |__  $$__/                 | $$          
| $$  \ $$ /$$   /$$| $$$$| $$  /$$$$$$  /$$$$$$  | $$  /$$$$$$   /$$$$$$ | $$  /$$$$$$$
| $$$$$$$/| $$  | $$| $$ $$ $$ /$$__  $$|_  $$_/  | $$ /$$__  $$ /$$__  $$| $$ /$$_____/
| $$____/ | $$  | $$| $$  $$$$| $$$$$$$$  | $$    | $$| $$  \ $$| $$  \ $$| $$|  $$$$$$ 
| $$      | $$  | $$| $$\  $$$| $$_____/  | $$ /$$| $$| $$  | $$| $$  | $$| $$ \____  $$
| $$      |  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/| $$|  $$$$$$/|  $$$$$$/| $$ /$$$$$$$/
|__/       \____  $$|__/  \__/ \_______/   \___/  |__/ \______/  \______/ |__/|_______/ 
           /$$  | $$                                                                    
          |  $$$$$$/                                                                    
           \______/                                                                     
           {Fore.RESET}  
by: alekszdev
            """
    print(logo)
    print(f"{Fore.CYAN}[{Fore.RESET}1{Fore.CYAN}]{Fore.RESET} PORT SCANNER")
    print(f"{Fore.CYAN}[{Fore.RESET}2{Fore.CYAN}]{Fore.RESET} IP LOCATION")
    print(f"{Fore.CYAN}[{Fore.RESET}3{Fore.CYAN}]{Fore.RESET} DNS LOOKUP")
    print(f"{Fore.CYAN}[{Fore.RESET}4{Fore.CYAN}]{Fore.RESET} DOMAIN INFO")
    print(f"{Fore.CYAN}[{Fore.RESET}5{Fore.CYAN}]{Fore.RESET} CHECK CONECTIVITY")
    try:
        option = int(input(f"> "))
        select_option(option)
        try_again()
    except ValueError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")
        try_again()
main_menu()

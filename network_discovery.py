import os
import subprocess
import ipaddress
from tabulate import tabulate
from colorama import Fore, Style, init
import time
import pickle

# Initialize colorama
init(autoreset=True)

# Cache file to store discovered Linux hosts
linux_hosts_cache_file = '/home/kali/Documents/capstone2_codes/linux_hosts_cache.pkl'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def cache_linux_hosts(linux_hosts):
    with open(linux_hosts_cache_file, 'wb') as f:
        pickle.dump(linux_hosts, f)

def load_cached_linux_hosts():
    if os.path.exists(linux_hosts_cache_file):
        with open(linux_hosts_cache_file, 'rb') as f:
            return pickle.load(f)
    return {}

def get_valid_subnet():
    underline = '\033[4m'
    reset_underline = '\033[24m'
    
    print(f"{Fore.BLUE}{Style.BRIGHT}{underline}Enter Subnet Information:{reset_underline}{Style.RESET_ALL}")
    while True:
        subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ").strip()
        try:
            if '/' not in subnet or len(subnet.split('/')) != 2:
                raise ValueError("Input must be in CIDR notation (e.g., 192.168.1.0/24)")
            network = ipaddress.IPv4Network(subnet, strict=False)
            return network
        except (ipaddress.AddressValueError, ValueError):
            print(f"{Fore.RED}Invalid subnet format. Please enter a valid subnet in CIDR notation (e.g., 192.168.1.0/24).{Style.RESET_ALL}")

def get_os_type(ip):
    try:
        result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "ttl=" in line.lower():
                    ttl = int(line.split('ttl=')[1].split()[0])
                    if ttl > 64 and ttl <= 128:
                        return "Windows"
                    elif ttl <= 64:
                        return "Linux"
                    elif ttl > 128 and ttl <= 255:
                        return "Network Device"
        return None
    except Exception as e:
        print(f"{Fore.RED}Error determining OS for {ip}: {str(e)}{Style.RESET_ALL}")
        return None

def scan_subnet_with_fping(subnet):
    live_hosts = {}
    # Further reduced interval and timeout for faster scanning
    command = ['fping', '-a', '-g', '-i', '1', '-t', '50', str(subnet)]
    
    start_time = time.time()

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        live_ips = result.stdout.splitlines()

        for ip in live_ips:
            if ip.endswith(".1") or ip.endswith(".2"):
                continue

            os_type = get_os_type(ip)
            if os_type:
                live_hosts[ip] = os_type

    except Exception as e:
        print(f"{Fore.RED}Error scanning subnet with fping: {str(e)}{Style.RESET_ALL}")

    end_time = time.time()
    print(f"{Fore.BLUE}Scanning subnet completed, total time elapsed: {end_time - start_time:.2f} seconds{Style.RESET_ALL}")

    return live_hosts

def main():
    clear_screen()  # Clear the screen at the start
    subnet = get_valid_subnet()
    
    live_hosts = scan_subnet_with_fping(subnet)

    if not live_hosts:
        print(f"{Fore.RED}No live hosts found in the subnet.{Style.RESET_ALL}")
        return

    underline = '\033[4m'
    reset_underline = '\033[24m'
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}{underline}Discovered Hosts:{reset_underline}{Style.RESET_ALL}\n")
    headers = ["IP Address", "Operating System"]
    table_data = [[ip, os] for ip, os in live_hosts.items()]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="fancy_grid")
    print(final_table_data)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{underline}Please select an option to run the security assessment on required devices:{reset_underline}{Style.RESET_ALL}")
    print("1. Windows Devices.")
    print("2. Linux Devices.")
    print("3. Network Devices.")
    print("4. Goto main menu.")

    choice = input("\nEnter your choice (1/2/3/4): ").strip()
    print()  # Adding a blank line for spacing after choice input

    if choice == '1':
        windows_hosts = {ip: os for ip, os in live_hosts.items() if os == "Windows"}
        if windows_hosts:
            from windows_assessment import main as windows_assessment_main
            windows_assessment_main(windows_hosts, subnet)  # Pass the subnet to the assessment function
        else:
            print(f"{Fore.RED}No Windows hosts were discovered for assessment.{Style.RESET_ALL}")
    elif choice == '2':
        linux_hosts = {ip: os for ip, os in live_hosts.items() if os == "Linux"}
        if linux_hosts:
            cache_linux_hosts(linux_hosts)  # Cache the discovered Linux hosts for future use
            from linux_assessment import main as linux_assessment_main
            linux_assessment_main(linux_hosts, subnet)  # Pass the subnet to the assessment function
        else:
            print(f"{Fore.RED}No Linux hosts were discovered for assessment.{Style.RESET_ALL}")
    elif choice == '3':
        network_devices = {ip: os for ip, os in live_hosts.items() if os == "Network Device"}
        if network_devices:
            from network_assessment import main as network_assessment_main
            network_assessment_main(network_devices, subnet)  # Pass network devices and subnet to the assessment function
        else:
            print(f"{Fore.RED}No network devices were discovered for assessment.{Style.RESET_ALL}")
    elif choice == '4':
        return
    else:
        print(f"{Fore.RED}Invalid choice! Please select a valid option.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

import os
import subprocess
import ipaddress
from tabulate import tabulate
from colorama import Fore, Style, init
import time
import threading
from datetime import datetime
from io import StringIO

# Initialize colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_valid_subnet():
    underline = '\033[4m'
    reset_underline = '\033[24m'
    
    print(f"{Fore.BLUE}{Style.BRIGHT}{underline}Enter Subnet Information{reset_underline}:{Style.RESET_ALL}")
    while True:
        subnet = input(f"{Fore.CYAN}Please enter the subnet (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
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
    command = ['fping', '-a', '-g', '-i', '1', '-t', '50', str(subnet)]
    
    start_time = time.time()

    print(f"{Fore.CYAN}{Style.BRIGHT}Scanning the subnet, please wait...{Style.RESET_ALL}")

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
    print(f"{Fore.GREEN}Subnet scan completed in {end_time - start_time:.2f} seconds.{Style.RESET_ALL}")

    return live_hosts

def nmap_scan(target_ip):
    command = f"nmap {target_ip} -Pn"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def parse_nmap_output(nmap_output):
    lines = nmap_output.splitlines()
    open_ports = []
    for line in lines:
        if "/tcp" in line:
            parts = line.split()
            port = parts[0]
            service = " ".join(parts[1:])
            open_ports.append((port, service))
    return open_ports

def nmap_enhanced_scan(target_ip, ports):
    vulnerability_table = []
    exploit_count = 0
    critical_high_vuln_count = 0
    for port in ports:
        command = f"nmap -A --script vulners -T4 -n {target_ip} -p{port}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        for line in result.stdout.splitlines():
            if "https://vulners.com/" in line:
                parts = line.strip('|').strip().split()
                vulnerability_name = parts[0]
                score = parts[1]
                try:
                    float_score = float(score)
                except ValueError:
                    continue
                url = parts[2]
                exploitable = "*EXPLOIT*" in line
                vulnerability_table.append((vulnerability_name, score, url, "YES" if exploitable else "NO", port))
                if exploitable or float_score >= 7.0:
                    critical_high_vuln_count += 1
                exploit_count += 1 if exploitable else 0
    return critical_high_vuln_count, vulnerability_table

def classify_vulnerabilities(vulnerability_table):
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    for _, score, _, _, _ in vulnerability_table:
        score_float = float(score)
        if score_float >= 7.0:
            if score_float >= 10.0:
                critical_count += 1
            elif score_float >= 8.0:
                high_count += 1
            else:
                medium_count += 1
        else:
            low_count += 1
    return critical_count, high_count, medium_count, low_count

def timer(start_time, stop_event):
    while not stop_event.is_set():
        elapsed_time = time.time() - start_time
        print(f"\r{Fore.YELLOW}Time elapsed: {elapsed_time:.2f} seconds{Style.RESET_ALL}", end='', flush=True)
        time.sleep(1)

def run_vulnerability_scan(ip, output_buffer):
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Falconzak Smart Eye is now scanning the open ports on {ip}.{Style.RESET_ALL}\n")
    output_buffer.write(f"\nFalconzak Smart Eye is now scanning the open ports on {ip}.\n")

    nmap_output = nmap_scan(ip)
    open_ports = parse_nmap_output(nmap_output)
    
    if not open_ports:
        message = f"{Fore.RED}No open ports detected. A firewall might be blocking the scan or the host is down.{Style.RESET_ALL}\n"
        print(message)
        output_buffer.write(message)
        return 1  # No vulnerabilities (score 1)

    message = f"{Fore.GREEN}Open ports detected:\n{Style.RESET_ALL}" + tabulate(open_ports, headers=["Port", "Service"]) + "\n"
    print(message)
    output_buffer.write(message)

    scan_ports = [port_info[0].split('/')[0] for port_info in open_ports]

    if scan_ports:
        print(f"\n{Fore.YELLOW}Scanning for vulnerabilities on the detected open ports...{Style.RESET_ALL}\n")
        output_buffer.write(f"\nScanning for vulnerabilities on the detected open ports...\n")

        start_time = time.time()
        stop_event = threading.Event()
        timer_thread = threading.Thread(target=timer, args=(start_time, stop_event))
        timer_thread.start()

        critical_high_vuln_count, vulnerability_table = nmap_enhanced_scan(ip, scan_ports)
        
        stop_event.set()
        timer_thread.join()

        # Print final elapsed time only once after the scan is complete
        print(f"\n{Fore.YELLOW}Scan completed in {time.time() - start_time:.2f} seconds.{Style.RESET_ALL}\n")
        output_buffer.write(f"\n\nScan completed in {time.time() - start_time:.2f} seconds.\n")

        message = tabulate(vulnerability_table, headers=["Vulnerability Name", "Score", "URL", "Exploitable", "Port"]) + "\n"
        print(message)
        output_buffer.write(message)

        critical_count, high_count, medium_count, low_count = classify_vulnerabilities(vulnerability_table)
        message = (
            f"\n{Fore.CYAN}Vulnerability Classification:{Style.RESET_ALL}\n"
            f"{'-'*60}\n"
            f"Critical Vulnerabilities: {critical_count}\n"
            f"High Vulnerabilities:    {high_count}\n"
            f"Medium Vulnerabilities:  {medium_count}\n"
            f"Low Vulnerabilities:     {low_count}\n"
        )
        print(message)
        output_buffer.write(message)

        message = f"\nExploitable vulnerabilities: {critical_high_vuln_count}\n"
        print(message)
        output_buffer.write(message)

        if critical_high_vuln_count > 0:
            return 0  # Vulnerabilities found (score 0)
    
    return 1  # No vulnerabilities (score 1)

def perform_vulnerability_assessment(live_hosts, output_buffer, os_type_filter=None):
    assessment_results = []
    total_score = 0

    for ip, os_type in live_hosts.items():
        if os_type_filter and os_type != os_type_filter:
            continue
        score = run_vulnerability_scan(ip, output_buffer)
        assessment_results.append([ip, os_type, score])
        total_score += score

    return assessment_results, total_score

def save_results_to_file(subnet, os_type, assessment_results, output_buffer):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    directory = '/home/kali/capstone2/vulnerability_scan_result/'
    os.makedirs(directory, exist_ok=True)
    
    sanitized_subnet = str(subnet).replace("/", "_")
    
    if os_type == "Windows":
        filename = f"{directory}{sanitized_subnet}_windows_{timestamp}.txt"
    elif os_type == "Linux":
        filename = f"{directory}{sanitized_subnet}_linux_{timestamp}.txt"
    elif os_type == "Network Device":
        filename = f"{directory}{sanitized_subnet}_network_{timestamp}.txt"
    else:
        filename = f"{directory}{sanitized_subnet}_All_devices_{timestamp}.txt"
    
    headers = ["IP Address", "Operating System", "Vulnerability Score"]
    final_table_data = tabulate(assessment_results, headers=headers, tablefmt="fancy_grid")
    
    overall_percentage = (sum([result[2] for result in assessment_results]) / len(assessment_results)) * 100 if assessment_results else 0

    with open(filename, 'w') as file:
        file.write(output_buffer.getvalue())  # Write all captured output to the file
        file.write(final_table_data)
        file.write(f"\n{Fore.GREEN}Overall Vulnerability Assessment Percentage: {overall_percentage:.2f}%{Style.RESET_ALL}\n")
        if overall_percentage == 0:
            file.write(f"\n{Fore.RED}Critical, High, or Exploitable Vulnerabilities detected. Immediate remediation is required.{Style.RESET_ALL}\n")
        file.write(f"\n{Fore.GREEN}{Style.BRIGHT}\033[4mNOTE: Falconzak SmartEye Pro assigns a score of 1 if no Critical, High, or Exploitable Vulnerabilities are found; otherwise, it assigns a score of 0.\033[24m{Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}Results have been saved to: {filename}{Style.RESET_ALL}")

def display_discovered_hosts(live_hosts, output_buffer):
    headers = ["IP Address", "Operating System"]
    table_data = [[ip, os] for ip, os in live_hosts.items()]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="fancy_grid")
    message = f"\n{Fore.GREEN}{Style.BRIGHT}Discovered Hosts:{Style.RESET_ALL}\n\n" + final_table_data + "\n"
    print(message)
    output_buffer.write(message)

def display_results(assessment_results, output_buffer):
    headers = ["IP Address", "Operating System", "Vulnerability Score"]
    final_table_data = tabulate(assessment_results, headers=headers, tablefmt="fancy_grid")
    message = final_table_data + "\n"
    print(message)
    output_buffer.write(message)

    total_score = sum([result[2] for result in assessment_results])
    overall_percentage = (total_score / len(assessment_results)) * 100 if assessment_results else 0

    if overall_percentage == 0:
        message = f"\n{Fore.RED}Critical, High, or Exploitable Vulnerabilities detected. Immediate remediation is required.{Style.RESET_ALL}\n"
        print(message)
        output_buffer.write(message)
    
    message = f"\n{Fore.GREEN}Overall Vulnerability Assessment Percentage: {overall_percentage:.2f}%{Style.RESET_ALL}\n"
    print(message)
    output_buffer.write(message)

    message = f"\n{Fore.GREEN}{Style.BRIGHT}\033[4mNOTE: Falconzak SmartEye Pro assigns a score of 1 if no Critical, High, or Exploitable Vulnerabilities are found; otherwise, it assigns a score of 0.\033[24m{Style.RESET_ALL}\n"
    print(message)
    output_buffer.write(message)

def main():
    clear_screen()
    subnet = get_valid_subnet()
    output_buffer = StringIO()

    live_hosts = scan_subnet_with_fping(subnet)

    if not live_hosts:
        print(f"{Fore.RED}No live hosts found in the subnet.{Style.RESET_ALL}")
        return

    display_discovered_hosts(live_hosts, output_buffer)

    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Vulnerability Assessment Options:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Perform vulnerability scan for {Fore.BLUE}Windows{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Perform vulnerability scan for {Fore.GREEN}Linux{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Perform vulnerability scan for {Fore.MAGENTA}Network Devices{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Perform vulnerability scan for {Fore.CYAN}All Devices{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Go to Main Menu")

        choice = input(f"\n{Fore.CYAN}Enter your choice (1/2/3/4/5): {Style.RESET_ALL}").strip()

        filtered_hosts = {ip: os for ip, os in live_hosts.items() if (choice == '1' and os == "Windows") or (choice == '2' and os == "Linux") or (choice == '3' and os == "Network Device")}

        if not filtered_hosts and choice not in ['4', '5']:
            print(f"{Fore.RED}No hosts of the selected type were found. Please select a different option.{Style.RESET_ALL}")
            continue

        if choice in ['1', '2', '3', '4']:
            if choice == '1':
                assessment_results, total_score = perform_vulnerability_assessment(filtered_hosts, output_buffer, os_type_filter="Windows")
            elif choice == '2':
                assessment_results, total_score = perform_vulnerability_assessment(filtered_hosts, output_buffer, os_type_filter="Linux")
            elif choice == '3':
                assessment_results, total_score = perform_vulnerability_assessment(filtered_hosts, output_buffer, os_type_filter="Network Device")
            elif choice == '4':
                assessment_results, total_score = perform_vulnerability_assessment(live_hosts, output_buffer)

            display_results(assessment_results, output_buffer)

            save_option = input(f"{Fore.CYAN}Would you like to save the results to a file? (y/n): {Style.RESET_ALL}").strip().lower()
            if save_option == 'y':
                save_results_to_file(subnet, "Windows" if choice == '1' else "Linux" if choice == '2' else "Network Device" if choice == '3' else "All Devices", assessment_results, output_buffer)

        elif choice == '5':
            print(f"{Fore.GREEN}Redirecting to Main Menu...{Style.RESET_ALL}")
            os.system('python3 /home/kali/Documents/capstone2_codes/main_menu.py')
            break
        else:
            print(f"{Fore.RED}Invalid choice! Please select a valid option.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

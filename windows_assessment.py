import os
import getpass
import winrm
import time
from tabulate import tabulate
from colorama import Fore, Style, init
from datetime import datetime
import threading
import subprocess

# Initialize colorama
init(autoreset=True)

def execute_command(ip, username, password, command):
    try:
        session = winrm.Session(target=ip, auth=(username, password), transport='ntlm')
        result = session.run_ps(command)
        if result.status_code == 0:
            return result.std_out.decode().strip()
        else:
            return None
    except Exception as e:
        return None

def perform_windows_security_checks(ip, username, password):
    score = 0
    results = []

    hostname = execute_command(ip, username, password, "hostname")
    if not hostname:
        hostname = "Unknown"

    firewall_status = execute_command(ip, username, password, "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled")
    firewall_score = 1 if firewall_status and "True" in firewall_status else 0
    results.append(firewall_score)
    score += firewall_score

    # Updated BitLocker check to only validate encryption for the E: drive
    bitlocker_status = execute_command(ip, username, password, "Get-BitLockerVolume -MountPoint 'E:' | Select-Object -ExpandProperty VolumeStatus")
    encryption_score = 1 if bitlocker_status and "FullyEncrypted" in bitlocker_status else 0
    results.append(encryption_score)
    score += encryption_score

    antimalware_status = execute_command(ip, username, password, "$lastUpdate = (Get-MpComputerStatus).AntivirusSignatureLastUpdated; $daysOld = (Get-Date) - $lastUpdate; $daysOld.Days")
    antimalware_score = 1 if antimalware_status and int(antimalware_status.strip()) <= 30 else 0
    results.append(antimalware_score)
    score += antimalware_score

    antivirus_status = execute_command(ip, username, password, "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
    antivirus_score = 1 if antivirus_status and "True" in antivirus_status else 0
    results.append(antivirus_score)
    score += antivirus_score

    defender_status = execute_command(ip, username, password, "Get-Service -Name WinDefend | Select-Object -ExpandProperty Status")
    defender_score = 1 if defender_status and "Running" in defender_status else 0
    results.append(defender_score)
    score += defender_score

    results.append(score)
    return hostname, results

def save_results(subnet, data):
    subnet_str = str(subnet).replace('/', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{subnet_str}_{timestamp}.txt"
    save_path = os.path.join("/home/kali/capstone2/windows_scan_result", filename)
    
    with open(save_path, "w") as f:
        f.write(data)
    
    print(f"{Fore.GREEN}Results saved to {save_path}{Style.RESET_ALL}")

def timer(stop_event):
    start_time = time.time()
    while not stop_event.is_set():
        elapsed_time = time.time() - start_time
        print(f"\r{Fore.YELLOW}Windows Security Assessment is in progress, time elapsed {elapsed_time:.2f} seconds{Style.RESET_ALL}", end="", flush=True)
        time.sleep(1)

def main(discovered_hosts, subnet):
    underline = '\033[4m'
    reset_underline = '\033[24m'

    print(f"{Fore.BLUE}{Style.BRIGHT}{underline}Windows Security Assessment:{reset_underline}{Style.RESET_ALL}")
    
    attempts = 0
    max_attempts = 3
    authenticated = False

    while attempts < max_attempts and not authenticated:
        username = input("Enter your Windows username: ")
        print()  # Adding a blank line for spacing after username input
        password = getpass.getpass("Enter your Windows password: ")

        # Test the credentials by executing a simple command on the first discovered host
        first_host = next(iter(discovered_hosts))
        test_result = execute_command(first_host, username, password, "hostname")

        if test_result:
            authenticated = True
        else:
            attempts += 1
            if attempts < max_attempts:
                print(f"{Fore.RED}Incorrect credentials. Please try again ({attempts}/{max_attempts}).{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Maximum attempts reached. Returning to main menu...{Style.RESET_ALL}")
                return

    # If authenticated, start the assessment
    stop_event = threading.Event()
    timer_thread = threading.Thread(target=timer, args=(stop_event,))
    timer_thread.start()

    table_data = []
    sl_no = 1
    total_firewall_score = 0
    total_encryption_score = 0
    total_antimalware_score = 0
    total_antivirus_score = 0
    total_defender_score = 0
    total_score = 0
    total_windows_hosts = len(discovered_hosts)
    remediation_ips = []  # Track all IPs for remediation, regardless of assessment score

    for ip, os_type in discovered_hosts.items():
        if os_type == "Windows":
            hostname, results = perform_windows_security_checks(ip, username, password)
            row = [sl_no, ip, hostname, "Windows"] + results
            table_data.append(row)
            total_firewall_score += results[0]
            total_encryption_score += results[1]
            total_antimalware_score += results[2]
            total_antivirus_score += results[3]
            total_defender_score += results[4]
            total_score += results[-1]
            sl_no += 1

            # Add all IPs for remediation, regardless of whether they passed or failed the assessment
            remediation_ips.append(ip)

    stop_event.set()
    timer_thread.join()

    headers = ["SL#", "Host IP", "Hostname", "OS", "Firewall Assessment", "Disk Encryption Assessment", "Antimalware Signature Assessment", "Antivirus Assessment", "Windows Defender Assessment", "Score"]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="pretty")

    max_score_per_assessment = total_windows_hosts * 1  # Adjusted for 1/0 scoring

    firewall_percentage = (total_firewall_score / max_score_per_assessment) * 100
    encryption_percentage = (total_encryption_score / max_score_per_assessment) * 100
    antimalware_percentage = (total_antimalware_score / max_score_per_assessment) * 100
    antivirus_percentage = (total_antivirus_score / max_score_per_assessment) * 100
    defender_percentage = (total_defender_score / max_score_per_assessment) * 100
    overall_percentage = (total_score / (max_score_per_assessment * 5)) * 100

    summary = (
        f"\n{Fore.CYAN}{Style.BRIGHT}{underline}Final Security Assessment Results:{reset_underline}{Style.RESET_ALL}\n"
        f"\n{final_table_data}\n"
        f"{Fore.YELLOW}{Style.BRIGHT}{underline}Assessment Summary:{reset_underline}{Style.RESET_ALL}\n"
        f"1. Total Windows Systems scanned: {total_windows_hosts}\n"
        f"2. Total Firewall Assessment score: {total_firewall_score}/{max_score_per_assessment} ({firewall_percentage:.2f}%)\n"
        f"3. Total Disk Encryption Assessment score: {total_encryption_score}/{max_score_per_assessment} ({encryption_percentage:.2f}%)\n"
        f"4. Total Antimalware Signature Assessment score: {total_antimalware_score}/{max_score_per_assessment} ({antimalware_percentage:.2f}%)\n"
        f"5. Total Antivirus Assessment score: {total_antivirus_score}/{max_score_per_assessment} ({antivirus_percentage:.2f}%)\n"
        f"6. Total Windows Defender Assessment score: {total_defender_score}/{max_score_per_assessment} ({defender_percentage:.2f}%)\n"
        f"\n{Fore.GREEN}{Style.BRIGHT}Final overall assessment score: {total_score}/{max_score_per_assessment * 5} ({overall_percentage:.2f}%)\n"
        f"\n{Fore.CYAN}{Style.BRIGHT}Falconzak SmartEye gives a score of 1 for passing an assessment and 0 for failing.{Style.RESET_ALL}\n"
    )
    
    print(summary)

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select the required option:{Style.RESET_ALL}")
    if overall_percentage == 100.0:
        print(f"1. Save the results and Go to Main Menu.")
        print(f"2. Don't Save. Go to Main Menu.")
    else:
        print(f"1. Save the results and Go to Main Menu.")
        print(f"2. Since the Security Posture is not 100%, do you want to run remediation by Falconzak SmartEye Pro?")

    user_choice = input("Enter your choice (1 or 2): ").strip()

    if user_choice == "1":
        save_results(subnet, summary)
        input(f"\n{Fore.CYAN}Press Enter to go to the main menu...{Style.RESET_ALL}")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    elif user_choice == "2":
        if overall_percentage == 100.0:
            subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
        else:
            if remediation_ips:
                # Use the correct format to pass the IPs as separate arguments along with the credentials
                subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/windows_remediation.py", username, password] + remediation_ips)
            else:
                print(f"{Fore.RED}No systems require remediation.{Style.RESET_ALL}")
                subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    discovered_hosts = {}  # Replace with actual discovered hosts
    subnet = "192.168.1.0/24"  # Replace with the actual subnet used for the scan

    if discovered_hosts:
        main(discovered_hosts, subnet)
    else:
        print(f"{Fore.RED}No Windows hosts were discovered for assessment.{Style.RESET_ALL}")

import os
import winrm
import getpass
from colorama import Fore, Style, init
from datetime import datetime
import sys
import subprocess
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

def execute_command(ip, username, password, command):
    try:
        session = winrm.Session(target=ip, auth=(username, password), transport='ntlm')
        result = session.run_ps(command)
        if result.status_code == 0:
            output = result.std_out.decode().strip()
            return output
        else:
            error_output = result.std_err.decode().strip()
            print(f"{Fore.RED}Command failed on {ip}. Error: {error_output}{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}Failed to execute command on {ip}: {e}{Style.RESET_ALL}")
        return None

def assess_and_remediate_system(ip, username, password):
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Starting assessment and remediation for {ip}{Style.RESET_ALL}")
    
    score = 0
    results = []

    # Assessment Logic
    hostname = execute_command(ip, username, password, "hostname")
    if not hostname:
        hostname = "Unknown"

    print(f"{Fore.YELLOW}Assessing Firewall status on {ip}...{Style.RESET_ALL}")
    firewall_status = execute_command(ip, username, password, "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled")
    firewall_score = 1 if firewall_status and "True" in firewall_status else 0
    if firewall_score == 0:
        print(f"{Fore.YELLOW}Firewall is disabled. Attempting to enable it on {ip}...{Style.RESET_ALL}")
        result = remediate_firewall(ip, username, password)
        if result:
            firewall_score = 1
        else:
            print(f"{Fore.RED}Failed to remediate the firewall on {ip}. Manual intervention required.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Firewall is already enabled on {ip}. No action required.{Style.RESET_ALL}")
    results.append(firewall_score)
    score += firewall_score

    print(f"{Fore.YELLOW}Assessing Disk Encryption on E: drive of {ip}...{Style.RESET_ALL}")
    bitlocker_status = execute_command(ip, username, password, "Get-BitLockerVolume -MountPoint 'E:' | Select-Object -ExpandProperty VolumeStatus")
    encryption_score = 1 if bitlocker_status and "FullyEncrypted" in bitlocker_status else 0
    if encryption_score == 0:
        print(f"{Fore.YELLOW}Disk Encryption is disabled on E:. Attempting to enable it on {ip}...{Style.RESET_ALL}")
        result = remediate_bitlocker(ip, username, password)
        if result:
            bitlocker_status_after = execute_command(ip, username, password, "Get-BitLockerVolume -MountPoint 'E:' | Select-Object -ExpandProperty VolumeStatus")
            if bitlocker_status_after and ("FullyEncrypted" in bitlocker_status_after or "EncryptionInProgress" in bitlocker_status_after):
                print(f"{Fore.GREEN}Disk Encryption successfully enabled or in progress on E: drive of {ip}.{Style.RESET_ALL}")
                encryption_score = 1
            else:
                print(f"{Fore.RED}Disk Encryption remediation failed on E: drive of {ip}. Manual intervention required.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to execute Disk Encryption remediation on E: drive of {ip}. Manual intervention required.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Disk Encryption is already enabled on E: drive of {ip}. No action required.{Style.RESET_ALL}")
    results.append(encryption_score)
    score += encryption_score

    print(f"{Fore.YELLOW}Assessing Antimalware Signature on {ip}...{Style.RESET_ALL}")
    antimalware_status = execute_command(ip, username, password, "$lastUpdate = (Get-MpComputerStatus).AntivirusSignatureLastUpdated; $daysOld = (Get-Date) - $lastUpdate; $daysOld.Days")
    antimalware_score = 1 if antimalware_status and int(antimalware_status.strip()) <= 30 else 0
    if antimalware_score == 0:
        print(f"{Fore.YELLOW}Antimalware signatures are outdated. Attempting to update them on {ip}...{Style.RESET_ALL}")
        result = remediate_antimalware(ip, username, password)
        if result:
            print(f"{Fore.GREEN}Antimalware signatures successfully updated on {ip}.{Style.RESET_ALL}")
            antimalware_score = 1
        else:
            print(f"{Fore.RED}Antimalware signature update failed on {ip}. Manual intervention required.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Antimalware signatures are up to date on {ip}. No action required.{Style.RESET_ALL}")
    results.append(antimalware_score)
    score += antimalware_score

    print(f"{Fore.YELLOW}Assessing Antivirus status on {ip}...{Style.RESET_ALL}")
    antivirus_status = execute_command(ip, username, password, "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
    antivirus_score = 1 if antivirus_status and "True" in antivirus_status else 0
    if antivirus_score == 0:
        print(f"{Fore.YELLOW}Antivirus is disabled. Attempting to enable it on {ip}...{Style.RESET_ALL}")
        result = remediate_antivirus(ip, username, password)
        if result:
            print(f"{Fore.GREEN}Antivirus successfully enabled on {ip}.{Style.RESET_ALL}")
            antivirus_score = 1
        else:
            print(f"{Fore.RED}Antivirus remediation failed on {ip}. Manual intervention required.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Antivirus is already active on {ip}. No action required.{Style.RESET_ALL}")
    results.append(antivirus_score)
    score += antivirus_score

    print(f"{Fore.YELLOW}Assessing Windows Defender status on {ip}...{Style.RESET_ALL}")
    defender_status = execute_command(ip, username, password, "Get-Service -Name WinDefend | Select-Object -ExpandProperty Status")
    defender_score = 1 if defender_status and "Running" in defender_status else 0
    if defender_score == 0:
        print(f"{Fore.YELLOW}Windows Defender is disabled. Attempting to start it on {ip}...{Style.RESET_ALL}")
        result = remediate_defender(ip, username, password)
        if result:
            print(f"{Fore.GREEN}Windows Defender successfully started on {ip}.{Style.RESET_ALL}")
            defender_score = 1
        else:
            print(f"{Fore.RED}Windows Defender remediation failed on {ip}. Manual intervention required.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Windows Defender is already running on {ip}. No action required.{Style.RESET_ALL}")
    results.append(defender_score)
    score += defender_score

    results.append(score)
    return hostname, results

def remediate_firewall(ip, username, password):
    # Using the working logic directly
    command = "Set-NetFirewallProfile -All -Enabled True"
    
    # Create a session and run the command
    try:
        session = winrm.Session(target=ip, auth=(username, password), transport='ntlm')
        result = session.run_ps(command)
        
        if result.status_code == 0:
            return True
        else:
            print(f"{Fore.RED}Failed to enable firewall on {ip}.{Style.RESET_ALL}")
            print(f"{Fore.RED}Error:\n{result.std_err.decode().strip()}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Failed to execute command on {ip}: {e}{Style.RESET_ALL}")
        return False

def remediate_bitlocker(ip, username, password):
    # Define the PowerShell command to enable BitLocker
    remediation_command = """
    $SecurePassword = ConvertTo-SecureString 'Passme@12345' -AsPlainText -Force
    Enable-BitLocker -MountPoint 'E:' -PasswordProtector -Password $SecurePassword -EncryptionMethod XtsAes256
    """
    return execute_command(ip, username, password, remediation_command.strip())

def remediate_antimalware(ip, username, password):
    remediation_command = "Update-MpSignature"
    return execute_command(ip, username, password, remediation_command)

def remediate_antivirus(ip, username, password):
    remediation_command = "Set-MpPreference -DisableRealtimeMonitoring $false"
    return execute_command(ip, username, password, remediation_command)

def remediate_defender(ip, username, password):
    remediation_command = "Start-Service -Name WinDefend"
    return execute_command(ip, username, password, remediation_command)

def save_results(subnet, data):
    subnet_str = str(subnet).replace('/', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{subnet_str}_{timestamp}.txt"
    save_path = os.path.join("/home/kali/capstone2/windows_scan_result", filename)
    
    with open(save_path, "w") as f:
        f.write(data)
    
    print(f"{Fore.GREEN}Results saved to {save_path}{Style.RESET_ALL}")

def main(discovered_hosts, subnet, username, password):
    underline = '\033[4m'
    reset_underline = '\033[24m'

    print(f"{Fore.BLUE}{Style.BRIGHT}{underline}Windows Security Assessment:{reset_underline}{Style.RESET_ALL}")
    
    # If authenticated, start the assessment and remediation process
    table_data = []
    sl_no = 1
    total_firewall_score = 0
    total_encryption_score = 0
    total_antimalware_score = 0
    total_antivirus_score = 0
    total_defender_score = 0
    total_score = 0
    total_windows_hosts = len(discovered_hosts)

    max_score_per_assessment = 1 * total_windows_hosts  # Adjusted for 1/0 scoring

    for ip in discovered_hosts:
        hostname, results = assess_and_remediate_system(ip, username, password)
        row = [sl_no, ip, hostname, "Windows"] + results
        table_data.append(row)
        total_firewall_score += results[0]
        total_encryption_score += results[1]
        total_antimalware_score += results[2]
        total_antivirus_score += results[3]
        total_defender_score += results[4]
        total_score += results[-1]
        sl_no += 1

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Following is the Security Posture Assessment after remediation.{Style.RESET_ALL}\n")

    headers = ["SL#", "Host IP", "Hostname", "OS", "Firewall Assessment", "Disk Encryption Assessment", "Antimalware Signature Assessment", "Antivirus Assessment", "Windows Defender Assessment", "Score"]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="pretty")

    print(final_table_data)

    firewall_percentage = (total_firewall_score / max_score_per_assessment) * 100
    encryption_percentage = (total_encryption_score / max_score_per_assessment) * 100
    antimalware_percentage = (total_antimalware_score / max_score_per_assessment) * 100
    antivirus_percentage = (total_antivirus_score / max_score_per_assessment) * 100
    defender_percentage = (total_defender_score / max_score_per_assessment) * 100
    overall_percentage = (total_score / (max_score_per_assessment * 5)) * 100

    summary = (
        f"{Fore.YELLOW}{Style.BRIGHT}Final Reassessment Summary:{Style.RESET_ALL}\n"
        f"1. Total Systems reassessed: {total_windows_hosts}\n"
        f"2. Total Firewall Assessment score: {total_firewall_score}/{max_score_per_assessment} ({firewall_percentage:.2f}%)\n"
        f"3. Total Disk Encryption Assessment score: {total_encryption_score}/{max_score_per_assessment} ({encryption_percentage:.2f}%)\n"
        f"4. Total Antimalware Signature Assessment score: {total_antimalware_score}/{max_score_per_assessment} ({antimalware_percentage:.2f}%)\n"
        f"5. Total Antivirus Assessment score: {total_antivirus_score}/{max_score_per_assessment} ({antivirus_percentage:.2f}%)\n"
        f"6. Total Windows Defender Assessment score: {total_defender_score}/{max_score_per_assessment} ({defender_percentage:.2f}%)\n"
        f"\n{Fore.GREEN}Final overall assessment score: {total_score}/{max_score_per_assessment * 5} ({overall_percentage:.2f}%)\n"
    )

    print(summary)

    # Final options
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select the required option:{Style.RESET_ALL}")
    print(f"1. Save the assessment result and Go to Main Menu")
    print(f"2. Don't save, Go to Main Menu")

    user_choice = input("Enter your choice (1 or 2): ").strip()

    if user_choice == "1":
        save_results(subnet, summary)
        input(f"\n{Fore.CYAN}Press Enter to go to the main menu...{Style.RESET_ALL}")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    elif user_choice == "2":
        input(f"\n{Fore.CYAN}Press Enter to go to the main menu...{Style.RESET_ALL}")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    else:
        print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")

if __name__ == "__main__":
    username = sys.argv[1]
    password = sys.argv[2]
    discovered_hosts = sys.argv[3:]  # Get IPs passed from the assessment script
    subnet = "192.168.1.0/24"  # Replace with the actual subnet used for the scan

    if discovered_hosts:
        main({ip: "Windows" for ip in discovered_hosts}, subnet, username, password)  # Convert IPs to a dictionary with "Windows" as OS type
    else:
        print(f"{Fore.RED}No Windows hosts were discovered for assessment.{Style.RESET_ALL}")

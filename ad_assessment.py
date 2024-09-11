import winrm
import os
from colorama import Fore, Style, init
import getpass
from tabulate import tabulate
import re
import subprocess
from datetime import datetime

# Initialize colorama
init()

def run_powershell_command(session, command):
    try:
        result = session.run_ps(command)
        if result.status_code == 0:
            return result.std_out.decode().strip()
        else:
            return f"Error: {result.std_err.decode().strip()}"
    except Exception as e:
        return f"Error: {str(e)}"

def audit_logs_assessment(session):
    print(f"{Fore.CYAN}Checking Audit Logs Assessment...{Style.RESET_ALL}")
    command = r'AuditPol /get /category:* | Select-String -Pattern "Logon|Logoff|Account Lockout|User Account Management|Security Group Management|Sensitive Privilege Use|Audit Policy Change|System Integrity|Authentication Policy Change" -Context 0,1 | Where-Object { $_ -notmatch "Kerberos|Other Logon/Logoff Events|Other Account Logon Events" }'
    result = run_powershell_command(session, command)
    success = "Error" not in result
    result_cleaned = result.replace("\n  ", "\n")
    result_cleaned = result_cleaned.replace(">", "").strip()  # Remove '>' symbols
    print(f"{Fore.GREEN}Audit Logs Assessment Successful:\n{result_cleaned}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Audit Logs Assessment Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def backup_assessment(session):
    print(f"{Fore.CYAN}Checking AD Policy Backup Assessment...{Style.RESET_ALL}")
    command = r'Get-ScheduledTask -TaskName "AD_BACKUP_DAILY" | Get-ScheduledTaskInfo | Select-Object TaskName, LastRunTime, LastTaskResult, NextRunTime, Status | Format-Table -AutoSize'
    result = run_powershell_command(session, command)
    
    if "Error" in result:
        print(f"{Fore.RED}AD Policy Backup Assessment Failed: {result}{Style.RESET_ALL}\n\n")
        return False
    
    last_run_time_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM))', result)
    next_run_time_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM))', result, re.IGNORECASE)

    if last_run_time_match and next_run_time_match:
        last_run_time_str = last_run_time_match.group(1)
        next_run_time_str = next_run_time_match.group(1)
        try:
            last_run_time = datetime.strptime(last_run_time_str, "%m/%d/%Y %I:%M:%S %p")
            next_run_time = datetime.strptime(next_run_time_str, "%m/%d/%Y %I:%M:%S %p")
            time_diff = next_run_time - last_run_time
            success = time_diff.total_seconds() / 3600 <= 12
            print(f"{Fore.GREEN}AD Policy Backup Assessment Successful: Last Run Time: {last_run_time}, Next Run Time: {next_run_time}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}AD Policy Backup Assessment Failed: Last Run Time: {last_run_time}, Next Run Time: {next_run_time}{Style.RESET_ALL}\n\n")
            return success
        except Exception as e:
            print(f"{Fore.RED}Error parsing times: {str(e)}{Style.RESET_ALL}\n\n")
            return False
    else:
        print(f"{Fore.RED}AD Policy Backup Assessment Failed: {result}{Style.RESET_ALL}\n\n")
        return False

def password_complexity_assessment(session):
    print(f"{Fore.CYAN}Checking Password Complexity...{Style.RESET_ALL}")
    command = r'Get-ADDefaultDomainPasswordPolicy | Select-Object -Property LockoutDuration, LockoutThreshold, LockoutObservationWindow, MinPasswordLength, ComplexityEnabled, PasswordHistoryCount, MaxPasswordAge, MinPasswordAge'
    result = run_powershell_command(session, command)
    success = "Error" not in result
    print(f"{Fore.GREEN}Password Complexity Assessment Successful:\n{result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Password Complexity Assessment Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def dnssec_assessment(session):
    print(f"{Fore.CYAN}Checking DNSSEC Assessment...{Style.RESET_ALL}")
    command = r'Get-DnsServerZone -Name "falconzak.com" | Select-Object ZoneName, IsSigned'
    result = run_powershell_command(session, command)
    success = "Error" not in result
    print(f"{Fore.GREEN}DNSSEC Assessment Successful:\n{result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}DNSSEC Assessment Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def antivirus_check(session):
    print(f"{Fore.CYAN}Checking Antivirus Status...{Style.RESET_ALL}")
    command = r'Get-MpComputerStatus | Select-Object -Property AMServiceEnabled, AntivirusSignatureLastUpdated'
    result = run_powershell_command(session, command)
    success = "Error" not in result
    print(f"{Fore.GREEN}Antivirus Status Check Successful:\n{result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Antivirus Status Check Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def firewall_check(session):
    print(f"{Fore.CYAN}Checking Firewall Status...{Style.RESET_ALL}")
    command = r'Get-NetFirewallProfile | Select-Object -Property Name, Enabled'
    result = run_powershell_command(session, command)
    success = "Error" not in result
    print(f"{Fore.GREEN}Firewall Status Check Successful:\n{result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Firewall Status Check Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def disk_encryption_check(session):
    print(f"{Fore.CYAN}Checking Disk Encryption Status...{Style.RESET_ALL}")
    command = r'Get-BitLockerVolume -MountPoint "E:" | Select-Object -Property MountPoint, VolumeStatus'
    result = run_powershell_command(session, command)
    success = "Error" not in result and "FullyEncrypted" in result
    print(f"{Fore.GREEN}E: Drive Encryption Status Check Successful: {result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}E: Drive Encryption Status Check Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def check_windows_update_status(session):
    print(f"{Fore.CYAN}Checking Pending Windows Updates...{Style.RESET_ALL}")
    command = """
    $criteria = "IsInstalled=0"
    $searcher = New-Object -ComObject Microsoft.Update.Searcher
    $result = $searcher.Search($criteria)
    $updates = $result.Updates

    if ($updates.Count -eq 0) {
        Write-Output "No pending updates"
        return
    }

    Write-Output "Pending Critical Installation Updates:"
    $criticalUpdates = $updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }
    $criticalUpdates | Select-Object Title, MsrcSeverity, Description | Format-List

    Write-Output "`nPending Important Installation Updates:"
    $importantUpdates = $updates | Where-Object { $_.MsrcSeverity -eq 'Important' }
    $importantUpdates | Select-Object Title, MsrcSeverity, Description | Format-List

    Write-Output "`nPending Other Installation Updates:"
    $otherUpdates = $updates | Where-Object { $_.MsrcSeverity -ne 'Critical' -and $_.MsrcSeverity -ne 'Important' }
    $otherUpdates | Select-Object Title, MsrcSeverity, Description | Format-List
    """
    result = run_powershell_command(session, command)
    success = "No pending updates" in result
    print(f"{Fore.GREEN}Windows Update Check Successful:\n{result}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Windows Update Check Failed: {result}{Style.RESET_ALL}\n\n")
    return success

def malware_signature_update(session):
    print(f"{Fore.CYAN}Checking Malware Signature Update Status...{Style.RESET_ALL}")
    command = r'(Get-MpComputerStatus).AntivirusSignatureLastUpdated'
    result = run_powershell_command(session, command)
    
    try:
        last_update_str = result.split("\n")[0]
        last_update_date = datetime.strptime(last_update_str, "%A, %B %d, %Y %I:%M:%S %p")
        days_since_update = (datetime.now() - last_update_date).days
        success = days_since_update <= 30
        print(f"{Fore.GREEN}Malware Signature Update Status Check Successful: Last Updated on {last_update_date}{Style.RESET_ALL}\n\n" if success else f"{Fore.RED}Malware Signature Update Status Check Failed: Last Updated on {last_update_date}{Style.RESET_ALL}\n\n")
        return success
    except Exception as e:
        print(f"{Fore.RED}Error parsing date: {str(e)}{Style.RESET_ALL}\n\n")
        return False

def main():
    while True:
        ip = input("Enter the IP of the AD server: ").strip()
        # Validate IP format
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            print(f"{Fore.RED}Invalid IP address format. Please enter a valid IP address.{Style.RESET_ALL}")
            continue
        domain = "falconzak"
        username = f"{domain}\\admin"
        password = getpass.getpass(f"Enter the password for {username}@{ip}: ")

        # Get the hostname by running the hostname command
        try:
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
            hostname = run_powershell_command(session, "hostname")
            # Check if the server is an AD server by running an AD-related command
            services_command = "Get-Service -Name NTDS"
            services_result = run_powershell_command(session, services_command)
            if "Error" in services_result:
                raise ValueError("This IP does not belong to an AD server. Please enter the IP of an AD server.")
            break  # Exit loop if everything is successful
        except ValueError as ve:
            print(f"{Fore.RED}{ve}{Style.RESET_ALL}")
            continue
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
            continue

    print("\n")
    print(f"{Fore.GREEN}{Style.BRIGHT}Falconzak SmartEye 2.0 is performing Security Assessment for AD Server:{Style.RESET_ALL}\n")
    print(tabulate([[f"{ip}", f"{hostname}"]], headers=["IP", "Hostname"], tablefmt="grid"))
    print("\n")

    assessments = [
        {"name": "Password Complexity Enabled", "function": password_complexity_assessment},
        {"name": "Audit Logs Assessment Enabled", "function": audit_logs_assessment},
        {"name": "AD Policy Backup Enabled", "function": backup_assessment},
        {"name": "Antivirus Enabled", "function": antivirus_check},
        {"name": "Firewall Enabled", "function": firewall_check},
        {"name": "Disc Encryption Enabled", "function": disk_encryption_check},
        {"name": "Malware Signature update is less than 30 days", "function": malware_signature_update},
        {"name": "Windows Updates Pending", "function": check_windows_update_status},
        {"name": "DNSSEC Enabled", "function": dnssec_assessment},
    ]

    results = []
    sl_no = 1
    total_score = 0

    full_output = ""

    for assessment in assessments:
        full_output += f"\nChecking {assessment['name']}...\n"
        result = assessment["function"](session)
        meets_criteria = "Yes" if result else "No"
        score = 1 if result else 0
        total_score += score
        results.append([sl_no, assessment["name"], meets_criteria.center(28), str(score).center(20)])
        sl_no += 1
        full_output += "\n\n"

    final_percentage = (total_score / len(assessments)) * 100

    print(f"\n{Style.BRIGHT}\033[4mAssessment Score :\033[0m{Style.RESET_ALL}\n")  # Manually adding underline
    print(tabulate(results, headers=["SL#", "Security_Assessment", "Meet_Assessment_Criteria", "Assessment_Score"], tablefmt="grid"))
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Falconzak SmartEye 2.0 has given a Final Score of : {total_score}/{len(assessments)} ({final_percentage:.2f}%){Style.RESET_ALL}")

    # After publishing the score, check the percentage to determine which options to display
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select the required option:{Style.RESET_ALL}")
    if final_percentage == 100.0:
        print(f"1. Save the results and Go to Main Menu.")
        print(f"2. Don't Save. Go to Main Menu.")
    else:
        print(f"1. Save the results and Go to Main Menu.")
        print(f"2. Since the Security Posture is not 100%, do you want to run remediation by Falconzak SmartEye 2.0?")

    user_choice = input("Enter your choice (1 or 2): ").strip()

    if user_choice == "1":
        save_path = "/home/kali/capstone2/ad_scan_result/"
        os.makedirs(save_path, exist_ok=True)
        file_name = f"AD_FULL_SCAN_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        full_path = os.path.join(save_path, file_name)

        with open(full_path, 'w') as f:
            f.write(f"Falconzak SmartEye 2.0 is performing Security Assessment for AD Server:\n\n")
            f.write(tabulate([[f"{ip}", f"{hostname}"]], headers=["IP", "Hostname"], tablefmt="grid"))
            f.write("\n\n")
            f.write(full_output)
            f.write(f"\n{Style.BRIGHT}\033[4mAssessment Score :\033[0m{Style.RESET_ALL}\n")
            f.write(tabulate(results, headers=["SL#", "Security_Assessment", "Meet_Assessment_Criteria", "Assessment_Score"], tablefmt="grid"))
            f.write(f"\n\nFinal Score: {total_score}/{len(assessments)} ({final_percentage:.2f}%)\n")

        print(f"{Fore.GREEN}Results saved to {full_path}{Style.RESET_ALL}")
        input(f"\nPress Enter to go to the main menu...")
        subprocess.run(['python3', '/home/kali/Documents/capstone2_codes/main_menu.py'])
    elif user_choice == "2":
        if final_percentage == 100.0:
            subprocess.run(['python3', '/home/kali/Documents/capstone2_codes/main_menu.py'])
        else:
            # Passing credentials and IP to the remediation script
            subprocess.run(['python3', '/home/kali/Documents/capstone2_codes/ad_remediation.py', ip, username, password])

if __name__ == "__main__":
    main()

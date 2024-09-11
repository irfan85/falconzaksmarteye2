import os
import winrm
import sys
from colorama import Fore, Style, init
from datetime import datetime
import subprocess
from tabulate import tabulate
import re
import time

# Initialize colorama
init(autoreset=True)

def execute_command(ip, username, password, command):
    try:
        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password), transport='ntlm')
        result = session.run_ps(command)
        if result.status_code == 0:
            return result.std_out.decode().strip()
        else:
            print(f"{Fore.RED}Command failed on {ip}. Error: {result.std_err.decode().strip()}{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}Failed to execute command on {ip}: {e}{Style.RESET_ALL}")
        return None

def remediate_firewall(ip, username, password):
    command = r'Set-NetFirewallProfile -All -Enabled True'
    return execute_command(ip, username, password, command)

def remediate_password_complexity(ip, username, password):
    command = r'Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12 -ComplexityEnabled $true -LockoutThreshold 5'
    return execute_command(ip, username, password, command)

def remediate_audit_logs(ip, username, password):
    command = r'AuditPol /set /category:"Logon/Logoff","Account Logon","Account Management","DS Access","Privilege Use","System","Policy Change" /success:enable /failure:enable'
    return execute_command(ip, username, password, command)

def remediate_backup_policy(ip, username, password):
    command = r'SchTasks /Change /TN "AD_BACKUP_DAILY" /ST 00:00'
    return execute_command(ip, username, password, command)

def remediate_antivirus(ip, username, password):
    command = r'Set-MpPreference -DisableRealtimeMonitoring $false'
    return execute_command(ip, username, password, command)

def remediate_disk_encryption(ip, username, password):
    command = r"""
    $SecurePassword = ConvertTo-SecureString 'Passme@12345' -AsPlainText -Force
    Enable-BitLocker -MountPoint 'E:' -PasswordProtector -Password $SecurePassword -EncryptionMethod XtsAes256
    """
    return execute_command(ip, username, password, command.strip())

def remediate_malware_signature_update(ip, username, password):
    command = r'Update-MpSignature'
    return execute_command(ip, username, password, command)

def remediate_dnssec(ip, username, password):
    command = r'Set-DnsServerPrimaryZone -Name "falconzak.com" -SecureDelegation $true'
    return execute_command(ip, username, password, command)

def assess_and_remediate_password_complexity(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Password Complexity Enabled on {ip}...{Style.RESET_ALL}")
    password_complexity_status = execute_command(ip, username, password, "Get-ADDefaultDomainPasswordPolicy | Select-Object -Property MinPasswordLength, ComplexityEnabled, LockoutThreshold")
    if password_complexity_status and "True" in password_complexity_status:
        print(f"{Fore.GREEN}Password complexity is already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Password complexity is not enabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_password_complexity(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        password_complexity_status_after = execute_command(ip, username, password, "Get-ADDefaultDomainPasswordPolicy | Select-Object -Property MinPasswordLength, ComplexityEnabled, LockoutThreshold")
        if password_complexity_status_after and "True" in password_complexity_status_after:
            print(f"{Fore.GREEN}Password complexity enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable Password Complexity on {ip}.{Style.RESET_ALL}")
            return 0

def assess_and_remediate_audit_logs(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Audit Logs Assessment Enabled on {ip}...{Style.RESET_ALL}")
    audit_logs_status = execute_command(ip, username, password, "AuditPol /get /category:* | Select-String -Pattern 'Logon|Logoff|Account Lockout|User Account Management|Security Group Management|Sensitive Privilege Use|Audit Policy Change|System Integrity|Authentication Policy Change'")
    if audit_logs_status and "Success" in audit_logs_status:
        print(f"{Fore.GREEN}Audit Logs are already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Audit Logs are not fully enabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_audit_logs(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        audit_logs_status_after = execute_command(ip, username, password, "AuditPol /get /category:* | Select-String -Pattern 'Logon|Logoff|Account Lockout|User Account Management|Security Group Management|Sensitive Privilege Use|Audit Policy Change|System Integrity|Authentication Policy Change'")
        if audit_logs_status_after and "Success" in audit_logs_status_after:
            print(f"{Fore.GREEN}Audit Logs enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable Audit Logs on {ip}.{Style.RESET_ALL}")
            return 0

def assess_and_remediate_backup_policy(ip, username, password):
    print(f"{Fore.YELLOW}Assessing AD Policy Backup Enabled on {ip}...{Style.RESET_ALL}")
    backup_policy_status = execute_command(ip, username, password, "Get-ScheduledTask -TaskName 'AD_BACKUP_DAILY' | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime, Status")
    if backup_policy_status and "LastRunTime" in backup_policy_status:
        # Similar parsing logic as the assessment script
        last_run_time_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM))', backup_policy_status)
        next_run_time_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM))', backup_policy_status, re.IGNORECASE)

        if last_run_time_match and next_run_time_match:
            last_run_time_str = last_run_time_match.group(1)
            next_run_time_str = next_run_time_match.group(1)
            last_run_time = datetime.strptime(last_run_time_str, "%m/%d/%Y %I:%M:%S %p")
            next_run_time = datetime.strptime(next_run_time_str, "%m/%d/%Y %I:%M:%S %p")
            time_diff = next_run_time - last_run_time
            if time_diff.total_seconds() / 3600 <= 12:
                print(f"{Fore.GREEN}Backup Policy is already configured correctly on {ip}. No action required.{Style.RESET_ALL}")
                return 1
            else:
                print(f"{Fore.RED}Backup Policy is not configured correctly. Performing remediation on {ip}...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Backup Policy timings are not valid. Performing remediation on {ip}...{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Backup Policy not found. Performing remediation on {ip}...{Style.RESET_ALL}")
    
    # Remediate
    remediate_backup_policy(ip, username, password)
    time.sleep(5)  # Wait before re-assessing
    backup_policy_status_after = execute_command(ip, username, password, "Get-ScheduledTask -TaskName 'AD_BACKUP_DAILY' | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime, Status")
    if backup_policy_status_after and "LastRunTime" in backup_policy_status_after:
        print(f"{Fore.GREEN}Backup Policy configured successfully on {ip}.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Failed to configure Backup Policy on {ip}.{Style.RESET_ALL}")
        return 0

def assess_and_remediate_antivirus(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Antivirus Enabled on {ip}...{Style.RESET_ALL}")
    antivirus_status = execute_command(ip, username, password, "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled")
    if antivirus_status and "True" in antivirus_status:
        print(f"{Fore.GREEN}Antivirus is already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Antivirus is not enabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_antivirus(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        antivirus_status_after = execute_command(ip, username, password, "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled")
        if antivirus_status_after and "True" in antivirus_status_after:
            print(f"{Fore.GREEN}Antivirus enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable Antivirus on {ip}.{Style.RESET_ALL}")
            return 0

def assess_and_remediate_firewall(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Firewall Enabled on {ip}...{Style.RESET_ALL}")
    firewall_status = execute_command(ip, username, password, "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled")
    if firewall_status and "True" in firewall_status:
        print(f"{Fore.GREEN}Firewall is already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Firewall is disabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_firewall(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        firewall_status_after = execute_command(ip, username, password, "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled")
        if firewall_status_after and "True" in firewall_status_after:
            print(f"{Fore.GREEN}Firewall enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable Firewall on {ip}.{Style.RESET_ALL}")
            return 0

def assess_and_remediate_disk_encryption(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Disc Encryption Enabled on {ip}...{Style.RESET_ALL}")
    disk_encryption_status = execute_command(ip, username, password, "Get-BitLockerVolume -MountPoint 'E:' | Select-Object -ExpandProperty VolumeStatus")
    if disk_encryption_status and "FullyEncrypted" in disk_encryption_status:
        print(f"{Fore.GREEN}Disk Encryption is already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Disk Encryption is not enabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_disk_encryption(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        disk_encryption_status_after = execute_command(ip, username, password, "Get-BitLockerVolume -MountPoint 'E:' | Select-Object -ExpandProperty VolumeStatus")
        if disk_encryption_status_after and "FullyEncrypted" in disk_encryption_status_after:
            print(f"{Fore.GREEN}Disk Encryption enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable Disk Encryption on {ip}.{Style.RESET_ALL}")
            return 0

def assess_and_remediate_malware_signature_update(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Malware Signature update is less than 30 days on {ip}...{Style.RESET_ALL}")
    malware_signature_status = execute_command(ip, username, password, "(Get-MpComputerStatus).AntivirusSignatureLastUpdated")
    try:
        last_update_str = malware_signature_status.split("\n")[0]
        last_update_date = datetime.strptime(last_update_str, "%A, %B %d, %Y %I:%M:%S %p")
        days_since_update = (datetime.now() - last_update_date).days
        if days_since_update <= 30:
            print(f"{Fore.GREEN}Malware signatures are already updated on {ip}. No action required.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Malware signatures are outdated. Performing remediation on {ip}...{Style.RESET_ALL}")
            remediate_malware_signature_update(ip, username, password)
            time.sleep(5)  # Wait before re-assessing
            malware_signature_status_after = execute_command(ip, username, password, "(Get-MpComputerStatus).AntivirusSignatureLastUpdated")
            last_update_str_after = malware_signature_status_after.split("\n")[0]
            last_update_date_after = datetime.strptime(last_update_str_after, "%A, %B %d, %Y %I:%M:%S %p")
            days_since_update_after = (datetime.now() - last_update_date_after).days
            if days_since_update_after <= 30:
                print(f"{Fore.GREEN}Malware signatures updated successfully on {ip}.{Style.RESET_ALL}")
                return 1
            else:
                print(f"{Fore.RED}Failed to update Malware Signatures on {ip}.{Style.RESET_ALL}")
                return 0
    except Exception as e:
        print(f"{Fore.RED}Error parsing date: {str(e)}{Style.RESET_ALL}")
        return 0

def assess_and_remediate_dnssec(ip, username, password):
    print(f"{Fore.YELLOW}Assessing DNSSEC Enabled on {ip}...{Style.RESET_ALL}")
    dnssec_status = execute_command(ip, username, password, "Get-DnsServerZone -Name 'falconzak.com' | Select-Object -ExpandProperty IsSigned")
    if dnssec_status and "True" in dnssec_status:
        print(f"{Fore.GREEN}DNSSEC is already enabled on {ip}. No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}DNSSEC is not enabled. Performing remediation on {ip}...{Style.RESET_ALL}")
        remediate_dnssec(ip, username, password)
        time.sleep(5)  # Wait before re-assessing
        dnssec_status_after = execute_command(ip, username, password, "Get-DnsServerZone -Name 'falconzak.com' | Select-Object -ExpandProperty IsSigned")
        if dnssec_status_after and "True" in dnssec_status_after:
            print(f"{Fore.GREEN}DNSSEC enabled successfully on {ip}.{Style.RESET_ALL}")
            return 1
        else:
            print(f"{Fore.RED}Failed to enable DNSSEC on {ip}.{Style.RESET_ALL}")
            return 0

def assess_windows_update_status(ip, username, password):
    print(f"{Fore.YELLOW}Assessing Windows Updates Pending on {ip}...{Style.RESET_ALL}")
    windows_update_status = execute_command(ip, username, password, """
    $criteria = "IsInstalled=0"
    $searcher = New-Object -ComObject Microsoft.Update.Searcher
    $result = $searcher.Search($criteria)
    $updates = $result.Updates

    if ($updates.Count -eq 0) {
        Write-Output "No pending updates"
    } else {
        Write-Output "Pending updates detected"
    }
    """)
    if windows_update_status and "No pending updates" in windows_update_status:
        print(f"{Fore.GREEN}Windows Update Assessment Successful: No action required.{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Windows Updates are pending to be installed. This requires manual intervention as server reboot is required.{Style.RESET_ALL}")
        return 0

def assess_and_remediate_system(ip, username, password):
    results = []
    score = 0

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Starting assessment and remediation for {ip}{Style.RESET_ALL}")

    results.append(("Password Complexity Enabled", assess_and_remediate_password_complexity(ip, username, password)))
    results.append(("Audit Logs Assessment Enabled", assess_and_remediate_audit_logs(ip, username, password)))
    results.append(("AD Policy Backup Enabled", assess_and_remediate_backup_policy(ip, username, password)))
    results.append(("Antivirus Enabled", assess_and_remediate_antivirus(ip, username, password)))
    results.append(("Firewall Enabled", assess_and_remediate_firewall(ip, username, password)))
    results.append(("Disc Encryption Enabled", assess_and_remediate_disk_encryption(ip, username, password)))
    results.append(("Malware Signature update is less than 30 days", assess_and_remediate_malware_signature_update(ip, username, password)))
    results.append(("Windows Updates Pending", assess_windows_update_status(ip, username, password)))
    results.append(("DNSSEC Enabled", assess_and_remediate_dnssec(ip, username, password)))

    score = sum(status for _, status in results)
    return score, results

def save_results(ip, data):
    ip_str = str(ip).replace('.', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ip_str}_Remediated_{timestamp}.txt"
    save_path = os.path.join("/home/kali/capstone2/ad_scan_result", filename)
    
    with open(save_path, "w") as f:
        f.write(data)
    
    print(f"{Fore.GREEN}Results saved to {save_path}{Style.RESET_ALL}")

def main():
    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    score, results = assess_and_remediate_system(ip, username, password)
    
    # Re-assessment and Final Results
    headers = ["SL#", "Security_Assessment", "Meet_Assessment_Criteria", "Assessment_Score"]
    final_results = [[idx+1, name, "Yes" if status == 1 else "No", str(status)] for idx, (name, status) in enumerate(results)]
    final_table = tabulate(final_results, headers=headers, tablefmt="grid")
    total_score = sum(status for _, status in results)
    max_score = len(results)
    percentage = (total_score / max_score) * 100

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Assessment Score After Remediation:\n{final_table}{Style.RESET_ALL}\n")
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Falconzak SmartEye 2.0 has given a Final Score of : {total_score}/{max_score} ({percentage:.2f}%) after remediation{Style.RESET_ALL}")
    
    # Final options
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select the required option:{Style.RESET_ALL}")
    print(f"1. Save the assessment result and Go to Main Menu")
    print(f"2. Don't save, Go to Main Menu")

    user_choice = input("Enter your choice (1 or 2): ").strip()

    if user_choice == "1":
        save_results(ip, final_table)
        input(f"\n{Fore.CYAN}Press Enter to go to the main menu...{Style.RESET_ALL}")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    elif user_choice == "2":
        input(f"\n{Fore.CYAN}Press Enter to go to the main menu...{Style.RESET_ALL}")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    else:
        print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

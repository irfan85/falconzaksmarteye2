import paramiko
from tabulate import tabulate
from colorama import Fore, Style, init
import getpass
import os
import subprocess
from datetime import datetime
import sys

# Initialize colorama
init(autoreset=True)

def execute_ssh_command(ssh, command, password=None, timeout=30):
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        if password:
            stdin.write(password + "\n")
            stdin.flush()
        stdout_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()
        if "[sudo] password for" in stderr_output and "is not in the sudoers file" in stderr_output:
            print(f"{Fore.RED}User does not have sudo privileges. Manual intervention required.{Style.RESET_ALL}")
            return None, stderr_output
        return stdout_output, stderr_output
    except Exception as e:
        print(f"{Fore.RED}Failed to execute command: {e}{Style.RESET_ALL}")
        return None, None

def check_sudo_privileges(ssh, password):
    command = "sudo -S -v"
    stdout_output, stderr_output = execute_ssh_command(ssh, command, password)
    if stderr_output and "is not in the sudoers file" in stderr_output:
        return False
    return True

def get_hostname(ssh):
    command = "hostname"
    stdout_output, stderr_output = execute_ssh_command(ssh, command)
    return stdout_output.strip() if stdout_output else "Unknown"

def check_antivirus_status(ssh, password):
    print(f"Antivirus Active - ", end="")
    command = "systemctl is-active clamav-daemon"
    stdout_output, stderr_output = execute_ssh_command(ssh, command, password)
    if stdout_output is None:
        return 0  # If the command fails due to lack of sudo privileges

    if stdout_output.strip().lower() == "inactive":
        print("No, attempting remediation...")
        remediation_command = f"sudo systemctl restart clamav-daemon"
        stdout_output, stderr_output = execute_ssh_command(ssh, remediation_command, password)
        if "Unit clamav-daemon.service not found" in stderr_output:
            print(f"{Fore.RED}Antivirus remediation failed: clamav-daemon service not found. Manual intervention required.{Style.RESET_ALL}")
            return 0
        elif stdout_output.strip().lower() == "active":
            print("Antivirus remediation completed successfully.")
            return 1
        else:
            print(f"{Fore.RED}Antivirus remediation failed: Manual intervention required.{Style.RESET_ALL}")
            return 0
    elif stdout_output.strip().lower() == "active":
        print("Yes, no action required.")
        return 1
    else:
        print(f"{Fore.RED}Antivirus status could not be determined. Manual intervention required.{Style.RESET_ALL}")
        return 0

def check_firewall_status(ssh, password):
    print(f"Firewall Active - ", end="")
    command = "systemctl is-active ufw"
    stdout_output, stderr_output = execute_ssh_command(ssh, command, password)
    if stdout_output is None:
        return 0  # If the command fails due to lack of sudo privileges

    if stdout_output.strip().lower() == "inactive":
        print("No, attempting remediation...")
        remediation_command = f"sudo systemctl restart ufw"
        stdout_output, stderr_output = execute_ssh_command(ssh, remediation_command, password)
        if "Unit ufw.service not found" in stderr_output:
            print(f"{Fore.RED}Firewall remediation failed: ufw service not found. Manual intervention required.{Style.RESET_ALL}")
            return 0
        elif stdout_output.strip().lower() == "active":
            print("Firewall remediation completed successfully.")
            return 1
        else:
            print(f"{Fore.RED}Firewall remediation failed: Manual intervention required.{Style.RESET_ALL}")
            return 0
    elif stdout_output.strip().lower() == "active":
        print("Yes, no action required.")
        return 1
    else:
        print(f"{Fore.RED}Firewall status could not be determined. Manual intervention required.{Style.RESET_ALL}")
        return 0

def check_password_complexity(ssh, password):
    print(f"Password Policy is accurate - ", end="")
    
    complexity_command = "sudo -S grep -E '^minlen|dcredit|ucredit|lcredit|ocredit|minclass' /etc/security/pwquality.conf"
    validity_command = "sudo -S grep -E '^PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs"
    
    complexity_output, _ = execute_ssh_command(ssh, complexity_command, password)
    validity_output, _ = execute_ssh_command(ssh, validity_command, password)
    
    if complexity_output is None or validity_output is None:
        return 0  # If the command fails due to lack of sudo privileges

    combined_output = complexity_output + "\n" + validity_output

    expected_values = {
        'dcredit': '2',
        'ucredit': '1',
        'lcredit': '1',
        'ocredit': '1',
        'minclass': '1',
        'minlen': '12',
        'PASS_MAX_DAYS': '90',
        'PASS_MIN_DAYS': '7',
        'PASS_WARN_AGE': '7'
    }

    def parse_values(output, expected_keys):
        parsed = {}
        for line in output.splitlines():
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key in expected_keys:
                    parsed[key] = value
            else:
                for key in expected_keys:
                    if line.startswith(key):
                        parsed[key] = line.split(None, 1)[1].strip()
        return parsed

    combined_values = parse_values(combined_output, expected_values.keys())

    def check_values(parsed, expected):
        for key, expected_value in expected.items():
            if key not in parsed or parsed[key] != expected_value:
                return False
        return True

    if check_values(combined_values, expected_values):
        print("Yes, no action required.")
        return 1
    else:
        print("No, attempting remediation...")
        remediation_commands = [
            f"sudo sed -i 's/^dcredit=.*/dcredit=-2/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^ucredit=.*/ucredit=-1/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^lcredit=.*/lcredit=-1/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^ocredit=.*/ocredit=-1/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^minclass=.*/minclass=1/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^minlen=.*/minlen=12/' /etc/security/pwquality.conf",
            f"sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
            f"sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs",
            f"sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs"
        ]
        for command in remediation_commands:
            execute_ssh_command(ssh, command, password)
        print("Password Policy remediation completed.")
        return 1

def check_no_password_accounts(ssh, password):
    print(f"No User account found without password - ", end="")
    command = "sudo -S awk -F: '($2 == \"\") {print $1}' /etc/shadow"
    stdout_output, _ = execute_ssh_command(ssh, command, password)
    if stdout_output is None:
        return 0  # If the command fails due to lack of sudo privileges

    if stdout_output.strip():
        print("No, attempting remediation...")
        # Split the output by lines to get the list of usernames with no passwords
        users_without_password = stdout_output.strip().splitlines()
        for user in users_without_password:
            print(f"Deleting user {user} with no password...")
            delete_command = f"sudo -S userdel {user}"
            execute_ssh_command(ssh, delete_command, password)
        print("Remediation completed: Users without passwords have been deleted.")
        return 1
    else:
        print("Yes, no action required.")
        return 1

def perform_remediation(ip, username, password, sl_no, cached_password=None):
    attempts = 3
    while attempts > 0:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if cached_password:
                password = cached_password

            ssh.connect(ip, username=username, password=password)
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}Connected to {ip}{Style.RESET_ALL}")

            if not check_sudo_privileges(ssh, password):
                print(f"{Fore.RED}User {username} does not have sudo privileges. Skipping remediation for {ip}.{Style.RESET_ALL}")
                return [sl_no, ip, "Unknown", 0, 0, 0, 0, "0/4"], None

            hostname = get_hostname(ssh)

            antivirus_score = check_antivirus_status(ssh, password)
            firewall_score = check_firewall_status(ssh, password)
            password_score = check_password_complexity(ssh, password)
            no_password_score = check_no_password_accounts(ssh, password)

            ssh.close()

            assessment_score = f"{antivirus_score + firewall_score + password_score + no_password_score}/4"
            return [sl_no, ip, hostname, antivirus_score, firewall_score, password_score, no_password_score, assessment_score], password

        except paramiko.AuthenticationException:
            attempts -= 1
            if attempts > 0:
                print(f"{Fore.RED}Authentication failed. You have {attempts} attempt(s) left.{Style.RESET_ALL}")
                password = getpass.getpass("Enter SSH password again: ")
            else:
                print(f"{Fore.RED}Authentication failed for {ip}. Skipping.{Style.RESET_ALL}")
                return [sl_no, ip, "Unknown", 0, 0, 0, 0, "0/4"], None
        except Exception as e:
            print(f"{Fore.RED}Failed to remediate {ip}: {e}{Style.RESET_ALL}")
            return [sl_no, ip, "Unknown", 0, 0, 0, 0, "0/4"], None

def save_results_to_file(results, summary):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/home/kali/capstone2/linux_scan_result/linux_remediated_{timestamp}.txt"

    with open(filename, 'w') as file:
        file.write(results + "\n\n" + summary)

    return filename

def main():
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Falconzak SmartEye 2.0 is now remediating, stay calm!{Style.RESET_ALL}\n")

    # Get dynamic failing IPs and credentials from the command line arguments passed by linux_assessment.py
    username = sys.argv[1]
    password = sys.argv[2]
    failing_ips = sys.argv[3:]

    if not failing_ips:
        print(f"{Fore.RED}No IPs provided for remediation. Exiting...{Style.RESET_ALL}")
        return

    table_data = []
    sl_no = 1
    antivirus_passed, firewall_passed, password_passed, no_password_passed = 0, 0, 0, 0
    total_scanned = len(failing_ips)
    cached_password = password

    for ip in failing_ips:
        row, cached_password = perform_remediation(ip, username, password, sl_no, cached_password)
        table_data.append(row)
        antivirus_passed += row[3]
        firewall_passed += row[4]
        password_passed += row[5]
        no_password_passed += row[6]
        sl_no += 1

    headers = ["SL#", "Host IP", "Hostname", "Antivirus Status Score", "Firewall Status Score", "Password Complexity Score", "No Password Accounts Score", "Assessment Score"]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="grid")

    print(f"\n{Fore.BLUE}{Style.BRIGHT}Final Remediation Status:{Style.RESET_ALL}")
    print(final_table_data)

    def print_summary(name, passed, total):
        percentage = (passed / total * 100) if total > 0 else 0
        return f"{Fore.CYAN}{Style.BRIGHT}{name} Passed: {passed}/{total} ({percentage:.2f}%) {Style.RESET_ALL}"

    overall_percentage = ((antivirus_passed + firewall_passed + password_passed + no_password_passed) / (total_scanned * 4)) * 100 if total_scanned > 0 else 0

    summary = (
        f"{print_summary('Antivirus Status', antivirus_passed, total_scanned)}\n"
        f"{print_summary('Firewall Status', firewall_passed, total_scanned)}\n"
        f"{print_summary('Password Complexity', password_passed, total_scanned)}\n"
        f"{print_summary('No Password Accounts', no_password_passed, total_scanned)}\n"
        f"{Fore.GREEN}{Style.BRIGHT}Overall Percentage : {overall_percentage:.2f}%{Style.RESET_ALL}"
    )

    print(summary)

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select the required option:{Style.RESET_ALL}")
    print(f"1. Save the remediated results and Go to Main Menu.")
    print(f"2. Don't save, go to Main Menu.")

    user_choice = input("Enter your choice (1 or 2): ").strip()

    if user_choice == "1":
        filename = save_results_to_file(final_table_data, summary)
        print(f"\nResults saved to: {filename}")
        input("\nPress Enter to return to the Main Menu...")
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    elif user_choice == "2":
        subprocess.run(["python3", "/home/kali/Documents/capstone2_codes/main_menu.py"])
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()

import paramiko
from tabulate import tabulate
from colorama import Fore, Style, init
import getpass
import os
from datetime import datetime
import subprocess

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
        return stdout_output, stderr_output
    except Exception as e:
        print(f"{Fore.RED}Failed to execute command: {e}{Style.RESET_ALL}")
        return None, None

def get_hostname(ssh):
    command = "hostname"
    stdout_output, stderr_output = execute_ssh_command(ssh, command)
    return stdout_output.strip() if stdout_output else "Unknown"

def check_antivirus_status(ssh):
    print(f"{Fore.YELLOW}Performing Antivirus Status Check{Style.RESET_ALL}")
    command = "systemctl is-active clamav-daemon"
    stdout_output, stderr_output = execute_ssh_command(ssh, command)
    if stdout_output.strip().lower() == "active":
        print(f"{Fore.GREEN}Antivirus is active{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Antivirus is not active{Style.RESET_ALL}")
        return 0

def check_firewall_status(ssh):
    print(f"{Fore.YELLOW}Performing Firewall Status Check{Style.RESET_ALL}")
    command = "systemctl is-active ufw"
    stdout_output, stderr_output = execute_ssh_command(ssh, command)
    if stdout_output.strip().lower() == "active":
        print(f"{Fore.GREEN}Firewall is active{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Firewall is not active{Style.RESET_ALL}")
        return 0

def check_password_complexity(ssh, password):
    print(f"{Fore.YELLOW}Performing Password Complexity Check{Style.RESET_ALL}")
    complexity_command = "sudo -S grep -E '^minlen|dcredit|ucredit|lcredit|ocredit|minclass' /etc/security/pwquality.conf"
    complexity_output, _ = execute_ssh_command(ssh, complexity_command, password)

    validity_command = "sudo -S grep -E '^PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs"
    validity_output, _ = execute_ssh_command(ssh, validity_command, password)

    expected_complexity = {
        'dcredit': '2',
        'ucredit': '1',
        'lcredit': '1',
        'ocredit': '1',
        'minclass': '1',
        'minlen': '12'
    }
    
    expected_validity = {
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

    complexity_values = parse_values(complexity_output, expected_complexity.keys())
    validity_values = parse_values(validity_output, expected_validity.keys())

    def check_values(parsed, expected):
        for key, expected_value in expected.items():
            if key not in parsed or parsed[key] != expected_value:
                return 0
        return 1

    complexity_score = check_values(complexity_values, expected_complexity)
    validity_score = check_values(validity_values, expected_validity)

    if complexity_score == 1 and validity_score == 1:
        print(f"{Fore.GREEN}Password complexity and validity are correctly configured{Style.RESET_ALL}")
        return 1
    else:
        print(f"{Fore.RED}Password complexity and/or validity are not correctly configured{Style.RESET_ALL}")
        return 0

def check_no_password_accounts(ssh, password):
    print(f"{Fore.YELLOW}Performing No Password Accounts Check{Style.RESET_ALL}")
    command = "sudo -S awk -F: '($2 == \"\") {print $1}' /etc/shadow"
    stdout_output, stderr_output = execute_ssh_command(ssh, command, password)
    if stdout_output.strip():
        print(f"{Fore.RED}Accounts without passwords found: {stdout_output}{Style.RESET_ALL}")
        return 0
    else:
        print(f"{Fore.GREEN}No accounts without passwords found.{Style.RESET_ALL}")
        return 1

def perform_linux_security_checks(ip, username, password, cached_password=None):
    attempts = 3
    while attempts > 0:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if cached_password:
                password = cached_password

            ssh.connect(ip, username=username, password=password)
            print(f"{Fore.GREEN}Connected to {ip}{Style.RESET_ALL}")

            hostname = get_hostname(ssh)
            print(f"{Fore.YELLOW}{Style.BRIGHT}Hostname (IP): {hostname} ({ip}){Style.RESET_ALL}")

            antivirus_score = check_antivirus_status(ssh)
            firewall_score = check_firewall_status(ssh)
            password_score = check_password_complexity(ssh, password)
            no_password_score = check_no_password_accounts(ssh, password)
            ssh.close()

            total_scanned = 4
            total_passed = antivirus_score + firewall_score + password_score + no_password_score
            assessment_score = f"{total_passed}/{total_scanned}"

            return hostname, antivirus_score, firewall_score, password_score, no_password_score, assessment_score, password

        except paramiko.AuthenticationException as e:
            attempts -= 1
            if attempts > 0:
                print(f"{Fore.RED}Authentication failed: {e}. You have {attempts} more attempt(s).{Style.RESET_ALL}")
                password = getpass.getpass("Enter SSH password again: ")
            else:
                print(f"{Fore.RED}Authentication failed after 3 attempts: {e}{Style.RESET_ALL}")
                return "Unknown", 0, 0, 0, 0, "0/4", None
        except Exception as e:
            print(f"{Fore.RED}Failed to connect to {ip}: {e}{Style.RESET_ALL}")
            return "Unknown", 0, 0, 0, 0, "0/4", None

def save_results_to_file(results, summary):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/home/kali/capstone2/linux_scan_result/linux_assessment_{timestamp}.txt"
    
    with open(filename, 'w') as file:
        file.write(results + "\n\n" + summary)
    
    return filename

def main(linux_hosts, subnet):
    username = input("Enter SSH username: ")
    password = getpass.getpass("Enter SSH password: ")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Falconzak SmartEye Pro is performing Security Assessment of the Linux Systems{Style.RESET_ALL}\n")

    table_data = []
    sl_no = 1
    antivirus_passed, firewall_passed, password_passed, no_password_passed = 0, 0, 0, 0
    total_scanned = len(linux_hosts)
    failing_ips = list(linux_hosts)  # Ensure it's a list, passing all IPs for remediation
    cached_password = None

    for ip in linux_hosts:
        print(f"{Fore.YELLOW}Starting checks for {ip}{Style.RESET_ALL}")
        hostname, antivirus_score, firewall_score, password_score, no_password_score, assessment_score, cached_password = perform_linux_security_checks(ip, username, password, cached_password)
        row = [sl_no, ip, hostname, antivirus_score, firewall_score, password_score, no_password_score, assessment_score]
        table_data.append(row)
        sl_no += 1

        # Count passed checks
        antivirus_passed += antivirus_score
        firewall_passed += firewall_score
        password_passed += password_score
        no_password_passed += no_password_score

    headers = ["SL#", "Host IP", "Hostname", "Antivirus Status Score", "Firewall Status Score", "Password Complexity Score", "No Password Accounts Score", "Assessment Score"]
    final_table_data = tabulate(table_data, headers=headers, tablefmt="grid")

    print(f"\n{Fore.BLUE}{Style.BRIGHT}Linux Security Assessment Results:{Style.RESET_ALL}")
    print(final_table_data)

    # Summary
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Following the assessment for every feature and overall summary:{Style.RESET_ALL}")

    def print_summary(name, passed, total):
        percentage = (passed / total * 100) if total > 0 else 0
        return f"{Fore.CYAN}{Style.BRIGHT}{name} Passed: {passed}/{total} ({percentage:.2f}%) {Style.RESET_ALL}"

    overall_percentage = ((
        (antivirus_passed + firewall_passed + password_passed + no_password_passed) / (total_scanned * 4) * 100
        ) if total_scanned > 0 else 0)

    summary = (
        f"{print_summary('Antivirus Status', antivirus_passed, total_scanned)}\n"
        f"{print_summary('Firewall Status', firewall_passed, total_scanned)}\n"
        f"{print_summary('Password Complexity', password_passed, total_scanned)}\n"
        f"{print_summary('No Password Accounts', no_password_passed, total_scanned)}\n"
        f"{Fore.GREEN}{Style.BRIGHT}Overall Percentage : {overall_percentage:.2f}%{Style.RESET_ALL}"
    )

    print(summary)

    if overall_percentage < 100:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Assessment completed. Select the required option:{Style.RESET_ALL}")
        print(f"1. Save the file and exit.")
        print(f"2. Since the assessment score is less than 100%, go to auto-remediation.\n")

        user_choice = input("Enter your choice (1 or 2): ").strip()

        if user_choice == "1":
            filename = save_results_to_file(final_table_data, summary)
            print(f"Results saved to {filename}")
        elif user_choice == "2":
            # Redirect to linux_remediation.py with all IPs and credentials
            remediation_command = ["python3", "/home/kali/Documents/capstone2_codes/linux_remediation.py", username, password] + failing_ips
            subprocess.run(remediation_command)
        else:
            print("Invalid choice. Exiting without saving.")
    else:
        save_option = input("Would you like to save the results to a file? (yes/no): ").strip().lower()
        if save_option in ['yes', 'y']:
            filename = save_results_to_file(final_table_data, summary)
            print(f"Results saved to {filename}")
        else:
            print("Results discarded.")

if __name__ == "__main__":
    linux_hosts = ["192.168.1.1", "192.168.1.2"]  # Replace with your IPs or network discovery results
    subnet = "192.168.1.0/24"  # Replace with your subnet
    main(linux_hosts, subnet)

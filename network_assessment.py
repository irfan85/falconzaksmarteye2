import paramiko
import time
from colorama import Fore, Style, init
from tabulate import tabulate
import getpass
import threading
import os
import sys
from datetime import datetime
from contextlib import redirect_stdout
import pickle

# Initialize colorama for colored output
init(autoreset=True)

# Caching IPs for which assessments were performed
assessment_cache_file = '/home/kali/Documents/capstone2_codes/assessment_cache.pkl'

def load_cached_ips():
    if os.path.exists(assessment_cache_file):
        with open(assessment_cache_file, 'rb') as f:
            return pickle.load(f)
    return {}

def save_cached_ips(cached_ips):
    with open(assessment_cache_file, 'wb') as f:
        pickle.dump(cached_ips, f)

def execute_ssh_command(shell, command):
    shell.send(command + '\n')
    time.sleep(2)
    output = shell.recv(9999).decode('utf-8').strip()
    return output

def normalize_output(output):
    return ' '.join(output.lower().split())

def validate_feature(shell, hostname, feature_name, commands, expected_values_list):
    match_status = []
    configuration_details = []

    for command, expected_values in zip(commands, expected_values_list):
        output = execute_ssh_command(shell, command)
        filtered_output = normalize_output(output.replace(command, '').replace(hostname.lower() + '#', '').strip())
        
        for expected_value in expected_values:
            if expected_value in filtered_output:
                configuration_details.append(expected_value)

        feature_status = all(normalize_output(value) in filtered_output for value in expected_values)

        match_status.append(1 if feature_status else 0)

    final_result = 1 if all(match_status) else 0
    config_status = "Configured" if final_result == 1 else "Not Configured"
    return final_result, config_status, configuration_details

def start_timer(stop_event):
    start_time = time.time()
    while not stop_event.is_set():
        elapsed_time = time.time() - start_time
        print(f"\rVerification in progress {elapsed_time:.2f} seconds", end="", flush=True)
        time.sleep(1)

def main(discovered_devices, subnet):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    cached_ips = load_cached_ips()

    for ip in discovered_devices.keys():
        cached_ips[ip] = None  # Cache the IP address, but leave the save path as None until saving is chosen

        print(f"\n{Fore.CYAN}{Style.BRIGHT}Your scanned Network device: {ip}{Style.RESET_ALL}")
        username = input("Enter the username: ")

        max_attempts = 3
        for attempt in range(max_attempts):
            password = getpass.getpass("Enter the password: ")

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password)

                print(f"\n{Fore.CYAN}Verifying current configuration of the router for security features:\n{Style.RESET_ALL}")

                stop_event = threading.Event()
                timer_thread = threading.Thread(target=start_timer, args=(stop_event,))
                timer_thread.start()

                shell = ssh.invoke_shell()
                shell.send('terminal length 0\n')
                time.sleep(1)
                shell.recv(9999)  # Clear initial output

                shell.send('show running-config | include hostname\n')
                time.sleep(1)
                hostname_output = shell.recv(9999).decode('utf-8').strip()
                hostname = hostname_output.split()[-1].lower() if "hostname" in hostname_output.lower() else "unknown"

                shell.send('enable\n')
                time.sleep(1)
                shell.send(password + '\n')
                time.sleep(1)
                shell.recv(9999)  # Clear output after entering enable mode

                features = [
                    ("Disable Unused Services", validate_feature(shell, hostname,
                        "Disable Unused Services",
                        ["show running-config | include service", "show running-config | include platform", "show running-config | include http"],
                        [["no service pad"], ["no platform punt-keepalive disable-kernel-core"], ["no ip http server", "no ip http secure-server"]])),
                    
                    ("Set Up Strong Passwords", validate_feature(shell, hostname,
                        "Set Up Strong Passwords",
                        ["show running-config | include security passwords min-length", "show running-config | include enable secret"],
                        [["security passwords min-length 10"], ["enable secret"]])),
                    
                    ("Configure Local and Role-Based Access Control (RBAC)", validate_feature(shell, hostname,
                        "Configure Local and Role-Based Access Control (RBAC)",
                        ["show running-config | include parser view"],
                        [["parser view"]])),
                    
                    ("Account Lockdown after 3 incorrect attempts in 60 sec", validate_feature(shell, hostname,
                        "Account Lockdown after 3 incorrect attempts in 60 sec",
                        ["show running-config | include login block-for"],
                        [["login block-for 300 attempts 3 within 60"]])),
                    
                    ("Limit Access via Access Control Lists (ACLs)", validate_feature(shell, hostname,
                        "Limit Access via Access Control Lists (ACLs)",
                        ["show running-config | include access-list"],
                        [["access-list 10 permit 192.168.14.0 0.0.0.255"]])),
                    
                    ("Enable Logging and Time Stamps", validate_feature(shell, hostname,
                        "Enable Logging and Time Stamps",
                        ["show running-config | include logging", "show running-config | include service timestamps"],
                        [["logging buffered", "logging console critical", "logging monitor informational", "logging trap warnings"], 
                        ["service timestamps debug datetime msec", "service timestamps log datetime msec"]])),
                    
                    ("Enable Syslog", validate_feature(shell, hostname,
                        "Enable Syslog",
                        ["show running-config | include logging host"],
                        [["logging host 192.168.14.100"]])),
                    
                    ("Enable Secure Management Protocols", validate_feature(shell, hostname,
                        "Enable Secure Management Protocols",
                        ["show running-config | include transport input", "show running-config | include ip ssh"],
                        [["transport input ssh"], ["ip ssh version 2"]])),
                    
                    ("Set Up Banner Messages", validate_feature(shell, hostname,
                        "Set Up Banner Messages",
                        ["show running-config | include banner login"],
                        [["banner login"]])),
                    
                    ("Configure SNMP Security", validate_feature(shell, hostname,
                        "Configure SNMP Security",
                        ["show running-config | include snmp-server"],
                        [["snmp-server group snmpv3group v3 auth", "snmp-server host 192.168.14.100 version 3 auth snmpv3user"]])),
                    
                    ("Enable and Configure NTP", validate_feature(shell, hostname,
                        "Enable and Configure NTP",
                        ["show running-config | include ntp"],
                        [["ntp server 192.168.14.2"]])),
                    
                    ("Implement Routing Protocol Authentication", validate_feature(shell, hostname,
                        "Implement Routing Protocol Authentication",
                        ["show running-config | section interface"],
                        [["ip ospf authentication key-chain"]])),
                    
                    ("Backup Configuration Regularly", validate_feature(shell, hostname,
                        "Backup Configuration Regularly",
                        ["show running-config | include archive"],
                        [["archive", "path tftp://192.168.14.100/router-archive"]])),
                    
                    ("Disable Unnecessary Interfaces", validate_feature(shell, hostname,
                        "Disable Unnecessary Interfaces",
                        ["show running-config | section interface"],
                        [["shutdown"]]))
                ]

                stop_event.set()
                timer_thread.join()

                print("\n")

                for index, feature in enumerate(features):
                    print(f"{Fore.YELLOW}Checking: {feature[0]}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Configured Values: {', '.join(feature[1][2]) if feature[1][2] else 'None'}{Style.RESET_ALL}\n")
                    time.sleep(1)

                headers = ["SL#", "Feature", "Configured", "Score"]
                table_data = [[index + 1, feature[0], feature[1][1], feature[1][0]] for index, feature in enumerate(features)]

                headline = f"Following table shows the Security Posture Assessment results for the router {ip} - {hostname.upper()}:\n"
                print(Fore.CYAN + Style.BRIGHT + headline + Style.RESET_ALL)
                print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

                final_score = sum([feature[1][0] for feature in features])
                total_features = len(features)
                percentage = (final_score / total_features) * 100

                print(f"\nFinal Score: {final_score}/{total_features} ({percentage:.2f}%)")

                # Remediation process if not 100%
                if final_score < total_features:
                    print(f"\n{Fore.YELLOW}Security Assessment of this Network Device {hostname.upper()} is not 100%.")
                    remediation_choice = input(f"Do you want to go through an auto-remediation process? (Y/N): {Style.RESET_ALL}").strip().lower()
                    if remediation_choice == 'y':
                        from network_remediation import remediate
                        print(f"\n{Fore.CYAN}Starting remediation process for {ip}...{Style.RESET_ALL}")
                        remediate(ip, username, password, features)  # Call the remediation script
                        # Provide an option to rescan the device
                        rescan_choice = input(f"\n{Fore.CYAN}Would you like to rescan the device after remediation? (Y/N): {Style.RESET_ALL}").strip().lower()
                        if rescan_choice == 'y':
                            main({ip: "Network Device"}, subnet)  # Rescan the same device
                        return

                save_choice = input("\nWould you like to save the results? (Y/N): ").strip().lower()
                if save_choice == 'y':
                    # Ensure the directory exists before saving the file
                    save_directory = "/home/kali/capstone2/network_devices_scan_result/"
                    os.makedirs(save_directory, exist_ok=True)

                    save_path = os.path.join(save_directory, f"{ip}_{timestamp}.txt")
                    cached_ips[ip] = save_path  # Cache the IP address and its report file path

                    with open(save_path, "a") as file:
                        with redirect_stdout(file):
                            print("\n" + headline)
                            print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
                            print(f"\nFinal Score: {final_score}/{total_features} ({percentage:.2f}%)\n")
                    print(f"\n{Fore.GREEN}Results saved successfully at {save_path}!{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}Results not saved.{Style.RESET_ALL}")

                ssh.close()
                break  # Break out of the loop if authentication is successful

            except paramiko.AuthenticationException:
                print(f"{Fore.RED}Incorrect password. {max_attempts - attempt - 1} attempts remaining.{Style.RESET_ALL}")
                if attempt < max_attempts - 1:
                    continue  # Allow the loop to retry with a new password
                else:
                    print(f"{Fore.RED}Maximum attempts reached. Exiting...{Style.RESET_ALL}")
                    break
            except Exception as e:
                print(f"{Fore.RED}Failed to connect to the router: {e}{Style.RESET_ALL}")
                break

    save_cached_ips(cached_ips)  # Save the cached IPs after processing

if __name__ == "__main__":
    discovered_devices = {}  # Replace with actual discovered hosts
    subnet = "192.168.1.0/24"  # Replace with the actual subnet used for the scan

    if discovered_devices:
        main(discovered_devices, subnet)
    else:
        print(f"{Fore.RED}No network devices were discovered for assessment.{Style.RESET_ALL}")

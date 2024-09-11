import time
import paramiko
from colorama import Fore, Style

def execute_ssh_command(shell, command):
    shell.send(command + '\n')
    time.sleep(2)
    output = shell.recv(9999).decode('utf-8').strip()
    return output

def remediate(ip, username, password, features):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    shell = ssh.invoke_shell()
    shell.send('enable\n')
    time.sleep(1)
    shell.send(password + '\n')
    time.sleep(1)
    shell.recv(9999)  # Clear output after entering enable mode

    print(f"\n{Fore.CYAN}Performing auto-remediation for {ip}...\n{Style.RESET_ALL}")

    for feature in features:
        if feature[1][0] == 0:  # Only remediate features with a score of 0
            print(f"\nRemediating: {feature[0]}")

            if feature[0] == "Disable Unused Services":
                commands = [
                    "configure terminal",
                    "no service pad",
                    "no platform punt-keepalive disable-kernel-core",
                    "no ip http server",
                    "no ip http secure-server",
                    "end"
                ]
                verification_command = "show running-config | include service|platform|http"

            elif feature[0] == "Set Up Strong Passwords":
                commands = [
                    "configure terminal",
                    "security passwords min-length 10",
                    "enable secret <your-secret-password>",  # Replace with your secret
                    "end"
                ]
                verification_command = "show running-config | include security|enable"

            elif feature[0] == "Configure Local and Role-Based Access Control (RBAC)":
                commands = [
                    "configure terminal",
                    "parser view <view-name>",  # Replace <view-name> with the appropriate view name
                    "secret <your-view-secret>",  # Replace with your view secret
                    "end"
                ]
                verification_command = "show running-config | include parser view"

            elif feature[0] == "Account Lockdown after 3 incorrect attempts in 60 sec":
                commands = [
                    "configure terminal",
                    "login block-for 300 attempts 3 within 60",
                    "end"
                ]
                verification_command = "show running-config | include login block-for"

            elif feature[0] == "Limit Access via Access Control Lists (ACLs)":
                commands = [
                    "configure terminal",
                    "access-list 10 permit 192.168.14.0 0.0.0.255",
                    "end"
                ]
                verification_command = "show running-config | include access-list"

            elif feature[0] == "Enable Logging and Time Stamps":
                commands = [
                    "configure terminal",
                    "logging buffered 4096",
                    "logging console critical",
                    "logging monitor informational",
                    "logging trap warnings",
                    "service timestamps debug datetime msec",
                    "service timestamps log datetime msec",
                    "end"
                ]
                verification_command = "show running-config | include logging|timestamps"

            elif feature[0] == "Enable Syslog":
                commands = [
                    "configure terminal",
                    "logging host 192.168.14.100",  # Replace with your syslog server IP
                    "end"
                ]
                verification_command = "show running-config | include logging host"

            elif feature[0] == "Enable Secure Management Protocols":
                commands = [
                    "configure terminal",
                    "line vty 0 4",
                    "transport input ssh",
                    "ip ssh version 2",
                    "end"
                ]
                verification_command = "show running-config | include transport input|ip ssh"

            elif feature[0] == "Set Up Banner Messages":
                commands = [
                    "configure terminal",
                    "banner login ^C Unauthorized access is prohibited! ^C",  # Replace with your banner message
                    "end"
                ]
                verification_command = "show running-config | include banner"

            elif feature[0] == "Configure SNMP Security":
                commands = [
                    "configure terminal",
                    "snmp-server group snmpv3group v3 auth",
                    "snmp-server host 192.168.14.100 version 3 auth snmpv3user",  # Replace with your SNMP host and user details
                    "end"
                ]
                verification_command = "show running-config | include snmp-server"

            elif feature[0] == "Enable and Configure NTP":
                commands = [
                    "configure terminal",
                    "ntp server 192.168.14.2",  # Replace with your NTP server IP
                    "end"
                ]
                verification_command = "show running-config | include ntp"

            elif feature[0] == "Implement Routing Protocol Authentication":
                commands = [
                    "configure terminal",
                    "interface <interface-name>",  # Replace with your interface
                    "ip ospf authentication key-chain <your-keychain>",  # Replace with your keychain
                    "end"
                ]
                verification_command = "show running-config | section interface"

            elif feature[0] == "Backup Configuration Regularly":
                commands = [
                    "configure terminal",
                    "archive",
                    "path tftp://192.168.14.100/router-archive",  # Replace with your TFTP server path
                    "end"
                ]
                verification_command = "show running-config | include archive"

            elif feature[0] == "Disable Unnecessary Interfaces":
                commands = [
                    "configure terminal",
                    "interface <interface-name>",  # Replace with the unnecessary interface
                    "shutdown",
                    "end"
                ]
                verification_command = "show running-config | section interface"

            else:
                print(f"{Fore.RED}Unknown feature: {feature[0]}. Skipping...{Style.RESET_ALL}")
                continue

            # Execute remediation commands
            for command in commands:
                shell.send(command + '\n')
                time.sleep(2)
                print(f"Executed: {command}")

            # Write memory after remediation
            shell.send("write memory\n")
            time.sleep(2)
            print("Executed: write memory")

            # After applying the commands, re-check the feature
            time.sleep(5)  # Introduce a delay to allow changes to take effect
            output = execute_ssh_command(shell, verification_command)
            print(f"Verification Output: {output}")

            # Check if the expected configuration is in place
            if feature[0] == "Enable and Configure NTP":
                if "ntp server 192.168.14.2" in output:
                    print(f"{Fore.GREEN}Remediation successful for {feature[0]}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Remediation failed for {feature[0]}. Manual intervention may be required.{Style.RESET_ALL}")
            else:
                if all(expected_value in output for expected_value in feature[1][2]):
                    print(f"{Fore.GREEN}Remediation successful for {feature[0]}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Remediation failed for {feature[0]}. Manual intervention may be required.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Remediation completed for {ip}.{Style.RESET_ALL}")
    ssh.close()

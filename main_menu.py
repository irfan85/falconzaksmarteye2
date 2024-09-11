import os
from colorama import Fore, Style, init
import shutil
import subprocess

# Initialize colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def center_text(text, width):
    """Centers the text based on the console width."""
    return text.center(width)

def show_banner():
    terminal_width = shutil.get_terminal_size().columns
    
    banner_lines = [
        "╔════════════════════════════════════════════════════════════╗",
        "║                                                            ║",
        "║       WELCOME TO FALCONZAK SMARTEYE Console 2.0            ║",
        "║                                                            ║",
        "╚════════════════════════════════════════════════════════════╝"
    ]
    
    for line in banner_lines:
        print(Fore.CYAN + Style.BRIGHT + center_text(line, terminal_width) + Style.RESET_ALL)

def show_unauthorized_access_warning():
    terminal_width = shutil.get_terminal_size().columns
    warning_message = "WARNING: Unauthorized access to this system is prohibited. All activities may be monitored and recorded."
    print(Fore.RED + Style.BRIGHT + center_text(warning_message, terminal_width) + Style.RESET_ALL)

def show_main_menu():
    underline = '\033[4m'
    reset_underline = '\033[24m'
    
    menu = f"""
{Fore.BLUE}{Style.BRIGHT}{underline}Please select an option to perform a task:{reset_underline}{Style.RESET_ALL}

╔════════════════════════════════════════════════════════════╗
║  A. Network Discovery, Scanning and Remediation.           ║
║  B. Network Vulnerability Scanning.                        ║
║  C. SSL Vulnerability Scanning.                            ║
║  D. Active Directory NIST Standard Assessment.             ║
║  E. Exit.                                                  ║
╚════════════════════════════════════════════════════════════╝
"""
    print(menu)
    choice = input(f"{Fore.CYAN}Enter your choice (A/B/C/D/E): {Style.RESET_ALL}").strip().upper()
    return choice

def run_script(script_path):
    try:
        result = subprocess.run(['python3', script_path], check=True)
        if result.returncode != 0:
            print(f"{Fore.RED}The script exited with errors.{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}An error occurred while running the script.{Style.RESET_ALL}")
    except PermissionError:
        print(f"{Fore.RED}Unauthorized access: You do not have the necessary permissions to execute this script.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")

def main():
    clear_screen()
    show_banner()
    show_unauthorized_access_warning()

    while True:
        choice = show_main_menu()
        
        if choice == 'A':
            run_script('/home/kali/Documents/capstone2_codes/network_discovery.py')
        elif choice == 'B':
            run_script('/home/kali/Documents/capstone2_codes/vulnarability_assessment.py')
        elif choice == 'C':
            run_script('/home/kali/Documents/capstone2_codes/ssl_vulnarability.py')
        elif choice == 'D':
            run_script('/home/kali/Documents/capstone2_codes/ad_assessment.py')
        elif choice == 'E':
            print(f"{Fore.GREEN}Exiting Falconzak SmartEye. Goodbye!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice! Please select a valid option.{Style.RESET_ALL}")
    
    # Exit the script explicitly
    exit(0)

if __name__ == "__main__":
    main()
